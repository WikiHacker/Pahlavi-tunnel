#!/usr/bin/env python3
"""Pahlavi Tunnel (core)

Reverse TCP tunnel with optional AutoSync.

This file is intentionally self-contained (no external deps) and keeps
backwards-compatibility with the existing manager script which pipes stdin.

Key improvements over the legacy implementation:
  - asyncio based (massively fewer OS threads)
  - safer TCP keepalive tuning (works even if Python lacks constants)
  - lower memory footprint per connection (no 256KB buffers + no thread stacks)
  - better pool handling (retry stale pool sockets instead of failing fast)
  - configurable tuning via environment variables

ENV tuning (optional):
  PAHLAVI_POOL             : override pool size (int)
  PAHLAVI_DIAL_TIMEOUT     : connect timeout seconds (float)
  PAHLAVI_POOL_WAIT        : wait for an EU socket on IR side (float)
  PAHLAVI_KEEPALIVE_SECS   : TCP keepalive idle+interval seconds (int)
  PAHLAVI_SOCKBUF          : SO_SNDBUF/SO_RCVBUF bytes (int, 0=don't set)
  PAHLAVI_COPY_CHUNK       : copy chunk size bytes (int)
  PAHLAVI_SYNC_INTERVAL    : sync interval seconds (float)
  PAHLAVI_LOG_LEVEL        : DEBUG/INFO/WARNING/ERROR (str)
  PAHLAVI_POOL_MAX_AGE     : recycle idle pool sockets older than this (seconds)
  PAHLAVI_DIAL_CONCURRENCY : max concurrent dial attempts to IR (int)
  PAHLAVI_IR_BIND          : IR bind address (default 0.0.0.0)
  PAHLAVI_EU_LOCAL_HOST    : EU local connect host (default 127.0.0.1)

Protocol (compat with previous versions):
  - EU connects to IR bridge_port and waits.
  - IR assigns a target port by sending 2 bytes (big-endian) to that EU socket.
  - EU connects to 127.0.0.1:<target_port> and then proxies.

Notes:
  - Run the same version on both servers.
  - For best stability, increase ulimit -n and enable TCP keepalive.
"""

from __future__ import annotations

import asyncio
import logging
import os
import resource
import signal
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple, Callable


# ------------------------- Helpers -------------------------


# ------------------------- stdin-driven interface -------------------------
def read_line(prompt: str | None = None) -> str:
    """Read one line from stdin (used by the bash manager). Returns "" on EOF."""
    if prompt:
        print(prompt, end="", flush=True)
    import sys
    s = sys.stdin.readline()
    if not s:
        return ""
    return s.strip()

def _env_int(name: str, default: int) -> int:
    try:
        v = os.environ.get(name)
        if v is None or v.strip() == "":
            return default
        return int(v)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        v = os.environ.get(name)
        if v is None or v.strip() == "":
            return default
        return float(v)
    except Exception:
        return default


def _env_str(name: str, default: str) -> str:
    try:
        v = os.environ.get(name)
        if v is None:
            return default
        v = v.strip()
        return v if v else default
    except Exception:
        return default


def _setup_logging() -> None:
    level_name = os.environ.get("PAHLAVI_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

def _bump_nofile(target: int = 65535) -> None:
    """Best-effort: raise RLIMIT_NOFILE soft limit up to 'target' (capped by hard limit).

    This helps stability under load (many concurrent sockets). Requires permissions to raise.
    """
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        cap = hard if hard != resource.RLIM_INFINITY else target
        new_soft = min(int(target), int(cap))
        if new_soft > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
            soft2, hard2 = resource.getrlimit(resource.RLIMIT_NOFILE)
            # logging may not be configured yet; print is ok early.
            print(f"[nofile] bumped soft {soft}->{soft2} (hard={hard2})")
        else:
            # Avoid noisy logs in production
            pass
    except Exception as e:
        print(f"[nofile] failed to bump: {e}")


log = logging.getLogger("pahlavi")


@dataclass(frozen=True)
class Tunables:
    dial_timeout: float = _env_float("PAHLAVI_DIAL_TIMEOUT", 5.0)
    pool_wait: float = _env_float("PAHLAVI_POOL_WAIT", 15.0)
    keepalive_secs: int = _env_int("PAHLAVI_KEEPALIVE_SECS", 20)

    # Old version forced 8MB buffers per socket, which can hurt stability at scale.
    # Default: don't override OS autotuning (set PAHLAVI_SOCKBUF to enable).
    sockbuf: int = _env_int("PAHLAVI_SOCKBUF", 0)

    # Copy chunk for proxying. Old was 256KB (too much RAM per connection).
    copy_chunk: int = _env_int("PAHLAVI_COPY_CHUNK", 64 * 1024)

    sync_interval: float = _env_float("PAHLAVI_SYNC_INTERVAL", 3.0)

    backlog_bridge: int = _env_int("PAHLAVI_BACKLOG_BRIDGE", 16384)
    backlog_ports: int = _env_int("PAHLAVI_BACKLOG_PORTS", 16384)
    backlog_sync: int = _env_int("PAHLAVI_BACKLOG_SYNC", 1024)

    # Backpressure threshold for asyncio StreamWriter buffer.
    drain_threshold: int = _env_int("PAHLAVI_DRAIN_THRESHOLD", 256 * 1024)

    # AutoSync protocol limit (can be >255 with PT1 framing).
    max_sync_ports: int = _env_int("PAHLAVI_MAX_SYNC_PORTS", 512)

    # Recycle idle reverse connections to reduce NAT idle-drop issues.
    pool_max_age: float = _env_float("PAHLAVI_POOL_MAX_AGE", 300.0)
    # Heartbeat pooled reverse connections (seconds). Helps NAT/CGNAT idle-drop.
    pool_ping_interval: float = _env_float("PAHLAVI_POOL_PING_INTERVAL", 10.0)


    # How often to scan/recycle too-old pooled connections.
    pool_recycle_interval: float = _env_float("PAHLAVI_POOL_RECYCLE_INTERVAL", 30.0)


    # Close proxied sessions if completely idle for this many seconds (0 = disabled).
    session_idle: float = _env_float("PAHLAVI_SESSION_IDLE", 600.0)


    # Optional global cap on concurrently active user sessions (0 = unlimited).
    max_sessions: int = _env_int("PAHLAVI_MAX_SESSIONS", 0)

    # Limit concurrent TCP dial attempts (prevents "connection storm" when IR is down)
    dial_concurrency: int = _env_int("PAHLAVI_DIAL_CONCURRENCY", 50)

    # Bind/Connect hosts
    ir_bind_host: str = _env_str("PAHLAVI_IR_BIND", "0.0.0.0")
    eu_local_host: str = _env_str("PAHLAVI_EU_LOCAL_HOST", "127.0.0.1")


T = Tunables()


# ------------------------- Auto pool sizing -------------------------

def auto_pool_size(role: str = "ir") -> int:
    """Pick a safe default pool size based on process FD limit + RAM.

    Override with env var PAHLAVI_POOL (positive int).

    The legacy implementation created one OS thread per pool connection.
    This asyncio rewrite makes that safe, so the previous heuristic becomes
    practical in real deployments.
    """

    env_pool = _env_int("PAHLAVI_POOL", 0)
    if env_pool > 0:
        return env_pool

    # File descriptor limit for this process
    try:
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        nofile = soft if soft and soft > 0 else 1024
    except Exception:
        nofile = 1024

    # Total RAM (best-effort)
    mem_mb = 0
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_kb = int(line.split()[1])
                    mem_mb = mem_kb // 1024
                    break
    except Exception:
        mem_mb = 0

    # Reserve room for listeners, logs, timewait bursts, and user sockets
    reserve = 800
    fd_budget = max(0, nofile - reserve)

    # IR side tends to have more concurrent user sockets; be more conservative
    frac = 0.22 if role.lower().startswith("ir") else 0.30
    fd_based = int(fd_budget * frac)

    # RAM cap (rough): allow ~250 pool per 1GB
    ram_based = int((mem_mb / 1024) * 250) if mem_mb else 500

    pool = min(fd_based, ram_based)

    # Clamp to sane bounds (override via PAHLAVI_POOL)
    if pool < 100:
        pool = 100
    if pool > 2000:
        pool = 2000
    return pool


# ------------------------- Socket tuning -------------------------

def _tcp_keepalive_constants() -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """Return (KEEPIDLE, KEEPINTVL, KEEPCNT) constants if we can.

    Some minimal Python builds do not expose TCP_KEEPIDLE/...
    even though the Linux kernel supports them.
    """

    idle = getattr(socket, "TCP_KEEPIDLE", None)
    intvl = getattr(socket, "TCP_KEEPINTVL", None)
    cnt = getattr(socket, "TCP_KEEPCNT", None)

    if idle is not None and intvl is not None and cnt is not None:
        return idle, intvl, cnt

    # Linux fallback numeric values
    if sys.platform.startswith("linux"):
        return 4, 5, 6

    return idle, intvl, cnt


def tune_tcp(sock: socket.socket) -> None:
    """Apply conservative per-socket TCP tuning."""

    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass

    if T.sockbuf and T.sockbuf > 0:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, T.sockbuf)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, T.sockbuf)
        except Exception:
            pass

    # Keepalive
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        kidle, kintvl, kcnt = _tcp_keepalive_constants()
        if kidle is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, kidle, int(T.keepalive_secs))
            except Exception:
                pass
        if kintvl is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, kintvl, int(T.keepalive_secs))
            except Exception:
                pass
        if kcnt is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, kcnt, 3)
            except Exception:
                pass
    except Exception:
        pass


def _tune_writer_socket(writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    if isinstance(sock, socket.socket):
        tune_tcp(sock)



async def _open_connection(host: str, port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Dial TCP with timeout + tuning."""

    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=T.dial_timeout)
    _tune_writer_socket(writer)
    return reader, writer


async def _close_writer(writer: Optional[asyncio.StreamWriter]) -> None:
    if writer is None:
        return
    try:
        writer.close()
    except Exception:
        return
    try:
        await writer.wait_closed()
    except Exception:
        pass


# ------------------------- Proxy core -------------------------

async def _pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    activity_cb: Optional[Callable[[], None]] = None,
) -> None:
    """Copy bytes from reader to writer with backpressure + clean shutdown.

    We keep this very defensive because under real-world loss/RESET conditions
    writers can disappear while we're still proxying.
    """
    try:
        while True:
            if T.session_idle > 0:
                data = await asyncio.wait_for(reader.read(T.copy_chunk), timeout=T.session_idle)
            else:
                data = await reader.read(T.copy_chunk)

            if not data:
                break

            if activity_cb:
                activity_cb()

            writer.write(data)

            # Backpressure: drain when buffer grows.
            transport = writer.transport
            if transport is not None and transport.get_write_buffer_size() > T.drain_threshold:
                await writer.drain()
    except asyncio.TimeoutError:
        # Idle too long
        pass
    except asyncio.CancelledError:
        raise
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception:
        pass
    finally:
        # Half-close destination so the other direction can finish cleanly if possible.
        try:
            writer.write_eof()
        except Exception:
            pass


async def proxy_bidirectional(
    a_reader: asyncio.StreamReader,
    a_writer: asyncio.StreamWriter,
    b_reader: asyncio.StreamReader,
    b_writer: asyncio.StreamWriter,
) -> None:
    """Bidirectional proxy between (a) and (b) with fast tear-down.

    When one direction ends, we cancel the other immediately to prevent
    "write on dead socket" cascades (which create jitter and log spam).
    Also enforces an optional session idle timeout.
    """
    last_activity = time.time()

    def touch() -> None:
        nonlocal last_activity
        last_activity = time.time()

    t1 = asyncio.create_task(_pipe(a_reader, b_writer, touch))
    t2 = asyncio.create_task(_pipe(b_reader, a_writer, touch))

    async def idle_watchdog() -> None:
        if T.session_idle <= 0:
            return
        while True:
            await asyncio.sleep(min(1.0, T.session_idle))
            if time.time() - last_activity > T.session_idle:
                # Cancel both directions
                for t in (t1, t2):
                    if not t.done():
                        t.cancel()
                return

    wd = asyncio.create_task(idle_watchdog())
    try:
        done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(t1, t2, return_exceptions=True)
    finally:
        wd.cancel()
        await asyncio.gather(_close_writer(a_writer), _close_writer(b_writer), return_exceptions=True)


# ------------------------- EU: detect listening TCP ports -------------------------

def _parse_listen_ports_from_proc(exclude: Set[int]) -> List[int]:
    """Fast Linux-only port discovery (LISTEN state) via /proc/net/tcp*"""

    ports: Set[int] = set()

    def parse_file(path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                next(f, None)  # header
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 4:
                        continue
                    local_hex = parts[1]
                    state = parts[3]
                    if state != "0A":
                        continue
                    try:
                        _ip_hex, port_hex = local_hex.split(":")
                        p = int(port_hex, 16)
                    except Exception:
                        continue
                    if 1 <= p <= 65535 and p not in exclude:
                        ports.add(p)
        except FileNotFoundError:
            return
        except Exception:
            return

    if sys.platform.startswith("linux"):
        parse_file("/proc/net/tcp")
        parse_file("/proc/net/tcp6")

    return sorted(ports)


def _parse_listen_ports_from_ss(exclude: Set[int]) -> List[int]:
    """Fallback to ss (slower)."""

    try:
        out = subprocess.check_output(["bash", "-lc", "ss -lnt | awk 'NR>1{print $4}'"], stderr=subprocess.DEVNULL)
        text = out.decode(errors="ignore")
    except Exception:
        return []

    ports: Set[int] = set()
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ":" not in ln:
            continue
        try:
            p = int(ln.rsplit(":", 1)[1])
        except Exception:
            continue
        if 1 <= p <= 65535 and p not in exclude:
            ports.add(p)
    return sorted(ports)


def get_listen_ports(exclude_bridge: int, exclude_sync: int) -> List[int]:
    exclude = {exclude_bridge, exclude_sync}
    ports = _parse_listen_ports_from_proc(exclude)
    if ports:
        return ports
    return _parse_listen_ports_from_ss(exclude)


# ------------------------- EU mode -------------------------

@dataclass
class EUConfig:
    iran_ip: str
    bridge_port: int
    sync_port: int
    pool_size: int
    enable_autosync: bool = True


async def eu_port_sync_loop(cfg: EUConfig, stop: asyncio.Event, dial_sem: asyncio.Semaphore) -> None:
    """Periodically send EU listening ports to IR sync_port."""

    backoff = 0.5
    last_warn = 0.0
    while not stop.is_set():
        writer: Optional[asyncio.StreamWriter] = None
        try:
            async with dial_sem:
                reader, writer = await _open_connection(cfg.iran_ip, cfg.sync_port)
            _ = reader  # unused
            backoff = 0.5
            log.info("[EU] AutoSync connected -> %s:%s", cfg.iran_ip, cfg.sync_port)

            while not stop.is_set():
                ports = get_listen_ports(cfg.bridge_port, cfg.sync_port)[: T.max_sync_ports]
                count = min(len(ports), max(0, int(T.max_sync_ports)))
                # PT1 framing: b'PT1' + u16 count + u16 ports... (fallback compatible on IR)
                payload = b"PT1" + struct.pack("!H", count) + b"".join(struct.pack("!H", p) for p in ports[:count])
                writer.write(payload)
                await writer.drain()
                await asyncio.sleep(T.sync_interval)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # Don't spam logs if AutoSync is disabled on IR side.
            now = time.time()
            if now - last_warn > 60:
                log.warning("[EU] AutoSync reconnecting: %s", e)
                last_warn = now
            else:
                log.debug("[EU] AutoSync reconnecting: %s", e)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 5.0)
        finally:
            await _close_writer(writer)


async def eu_reverse_worker(cfg: EUConfig, worker_id: int, stop: asyncio.Event, dial_sem: asyncio.Semaphore) -> None:
    """Maintain one reverse bridge connection (idle until IR assigns a port)."""

    # Stagger initial connects a bit to avoid a big SYN burst on startup.
    await asyncio.sleep(min(0.5, (worker_id % 50) * 0.01))

    backoff = 0.2

    while not stop.is_set():
        writer: Optional[asyncio.StreamWriter] = None
        try:
            async with dial_sem:
                reader, writer = await _open_connection(cfg.iran_ip, cfg.bridge_port)
            created_at = time.time()
            backoff = 0.2

            # Wait for a 2-byte port assignment from IR.
            # IR may occasionally send port=0 as a lightweight heartbeat for idle pool sockets.
            while True:
                hdr = await reader.readexactly(2)
                (target_port,) = struct.unpack("!H", hdr)
                if target_port == 0:
                    # heartbeat - stay idle
                    continue
                if not (1 <= target_port <= 65535):
                    raise ValueError(f"Invalid target port: {target_port}")
                break

            # Connect to local service

            # Connect to local service
            l_reader, l_writer = await _open_connection(T.eu_local_host, target_port)

            # Proxy until done
            await proxy_bidirectional(reader, writer, l_reader, l_writer)

            # Proactively recycle extremely old connections (rare)
            if time.time() - created_at > T.pool_max_age:
                await _close_writer(writer)

        except asyncio.IncompleteReadError:
            # IR closed (or network drop)
            pass
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.debug("[EU:%d] worker error: %s", worker_id, e)
        finally:
            await _close_writer(writer)

        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 5.0)



async def _supervise_task(name: str, stop: asyncio.Event, coro_factory, backoff_start: float = 0.2) -> None:
    backoff = backoff_start
    while not stop.is_set():
        try:
            await coro_factory()
            if not stop.is_set():
                log.warning("[%s] Task exited; restarting", name)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            if not stop.is_set():
                log.warning("[%s] crashed: %s (restart in %.1fs)", name, e, backoff)
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 5.0)

async def run_eu(cfg: EUConfig) -> None:
    stop = asyncio.Event()

    dial_sem = asyncio.Semaphore(max(1, int(T.dial_concurrency)))

    loop = asyncio.get_running_loop()
    def _eh(loop, context):
        msg = context.get("message")
        exc = context.get("exception")
        log.warning("[IR] loop exception: %s %s", msg, exc)
    loop.set_exception_handler(_eh)
    def _eh(loop, context):
        msg = context.get("message")
        exc = context.get("exception")
        log.warning("[EU] loop exception: %s %s", msg, exc)
    loop.set_exception_handler(_eh)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    tasks: List[asyncio.Task] = []
    if cfg.enable_autosync:
        tasks.append(asyncio.create_task(_supervise_task("EU:sync", stop, lambda: eu_port_sync_loop(cfg, stop, dial_sem))))
    else:
        log.info("[EU] AutoSync disabled by config")
    for i in range(cfg.pool_size):
        wid = i + 1
        tasks.append(asyncio.create_task(_supervise_task(f"EU:worker:{wid}", stop, lambda wid=wid: eu_reverse_worker(cfg, wid, stop, dial_sem))))

    log.info(
        "[EU] Running | IRAN=%s bridge=%d sync=%d pool=%d",
        cfg.iran_ip,
        cfg.bridge_port,
        cfg.sync_port,
        cfg.pool_size,
    )

    await stop.wait()

    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


# ------------------------- IR mode -------------------------

@dataclass
class IRConfig:
    bridge_port: int
    sync_port: int
    pool_size: int
    auto_sync: bool
    manual_ports: List[int]


@dataclass
class PooledConn:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    created_at: float


class BridgePool:
    def __init__(self, maxsize: int):
        self._q: asyncio.Queue[PooledConn] = asyncio.Queue(maxsize=maxsize)

    def qsize(self) -> int:
        return self._q.qsize()

    async def put(self, item: PooledConn) -> bool:
        try:
            self._q.put_nowait(item)
            return True
        except asyncio.QueueFull:
            return False

    async def get(self, timeout: float) -> Optional[PooledConn]:
        try:
            return await asyncio.wait_for(self._q.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def recycle_stale(self) -> int:
        """Remove connections older than pool_max_age from the queue."""

        removed = 0
        now = time.time()
        items: List[PooledConn] = []

        while True:
            try:
                items.append(self._q.get_nowait())
            except asyncio.QueueEmpty:
                break

        for it in items:
            if now - it.created_at > T.pool_max_age:
                removed += 1
                await _close_writer(it.writer)
            else:
                try:
                    self._q.put_nowait(it)
                except asyncio.QueueFull:
                    await _close_writer(it.writer)

        return removed


async def ir_accept_bridge(cfg: IRConfig, pool: BridgePool) -> None:
    """Accept EU reverse connections and add them to pool."""

    async def on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        _tune_writer_socket(writer)
        item = PooledConn(reader=reader, writer=writer, created_at=time.time())
        ok = await pool.put(item)
        if not ok:
            await _close_writer(writer)

    server = await asyncio.start_server(
        on_connect,
        host=T.ir_bind_host,
        port=cfg.bridge_port,
        backlog=T.backlog_bridge,
        reuse_address=True,
    )

    addrs = ", ".join(str(sock.getsockname()) for sock in (server.sockets or []))
    log.info("[IR] Bridge listening on %s", addrs)

    async with server:
        await server.serve_forever()


async def ir_sync_listener(cfg: IRConfig, open_port_cb) -> None:
    """Receive port list from EU and open corresponding ports on IR."""

    async def on_sync(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        _tune_writer_socket(writer)
        try:
            while True:
                # Try new framing first: b'PT1' + u16 count + ports...
                peek = await reader.readexactly(3)
                if peek == b"PT1":
                    (count,) = struct.unpack("!H", await reader.readexactly(2))
                    count = min(count, max(0, int(T.max_sync_ports)))
                    ports: Set[int] = set()
                    for _ in range(count):
                        (p,) = struct.unpack("!H", await reader.readexactly(2))
                        if 1 <= p <= 65535:
                            ports.add(p)
                    await open_port_cb(ports)
                    continue

                # Legacy framing fallback: 1-byte count already read as peek[0]
                count = peek[0]
                ports: Set[int] = set()
                for _ in range(count):
                    (p,) = struct.unpack("!H", await reader.readexactly(2))
                    if 1 <= p <= 65535:
                        ports.add(p)
                await open_port_cb(ports)
        except asyncio.IncompleteReadError:
            pass
        except Exception:
            pass
        finally:
            await _close_writer(writer)

    server = await asyncio.start_server(
        on_sync,
        host=T.ir_bind_host,
        port=cfg.sync_port,
        backlog=T.backlog_sync,
        reuse_address=True,
    )

    addrs = ", ".join(str(sock.getsockname()) for sock in (server.sockets or []))
    log.info("[IR] Sync listening on %s (AutoSync)", addrs)

    async with server:
        await server.serve_forever()


async def ir_handle_user(
    user_reader: asyncio.StreamReader,
    user_writer: asyncio.StreamWriter,
    target_port: int,
    pool: BridgePool,
) -> None:
    _tune_writer_socket(user_writer)

    deadline = time.time() + T.pool_wait
    europe: Optional[PooledConn] = None

    # Try multiple times: pool might contain stale sockets.
    while time.time() < deadline:
        remaining = max(0.1, deadline - time.time())
        cand = await pool.get(timeout=remaining)
        if cand is None:
            break

        # Recycle too-old pool sockets (helps NAT)
        if time.time() - cand.created_at > T.pool_max_age:
            await _close_writer(cand.writer)
            continue

        try:
            cand.writer.write(struct.pack("!H", target_port))
            await cand.writer.drain()
            europe = cand
            break
        except Exception:
            await _close_writer(cand.writer)
            continue

    if europe is None:
        await _close_writer(user_writer)
        return

    try:
        await proxy_bidirectional(user_reader, user_writer, europe.reader, europe.writer)
    except Exception:
        await _close_writer(user_writer)
        await _close_writer(europe.writer)


async def run_ir(cfg: IRConfig) -> None:
    stop = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    pool = BridgePool(maxsize=cfg.pool_size * 2)


    session_sem: Optional[asyncio.Semaphore] = None
    if T.max_sessions and T.max_sessions > 0:
        session_sem = asyncio.Semaphore(T.max_sessions)
    
    async def _with_session_limit(coro):
        if session_sem is None:
            return await coro
        await session_sem.acquire()
        try:
            return await coro
        finally:
            session_sem.release()
    
    async def pool_pinger() -> None:
        # Send lightweight heartbeat (port=0) over idle pool sockets to keep NAT mappings alive.
        if T.pool_ping_interval <= 0:
            return
        while not stop.is_set():
            await asyncio.sleep(T.pool_ping_interval)
            items: List[PooledConn] = []
            while True:
                try:
                    items.append(pool._q.get_nowait())
                except asyncio.QueueEmpty:
                    break
            for it in items:
                # Drop too-old
                if time.time() - it.created_at > T.pool_max_age:
                    await _close_writer(it.writer)
                    continue
                try:
                    it.writer.write(struct.pack("!H", 0))
                    await asyncio.wait_for(it.writer.drain(), timeout=1.0)
                    await pool.put(it)
                except Exception:
                    await _close_writer(it.writer)
    
    async def pool_recycler() -> None:
        if T.pool_recycle_interval <= 0:
            return
        while not stop.is_set():
            await asyncio.sleep(T.pool_recycle_interval)
            try:
                removed = await pool.recycle_stale()
                if removed:
                    log.debug("[IR] Recycled %d stale pooled conns", removed)
            except Exception:
                pass
    
        active_ports: Dict[int, asyncio.AbstractServer] = {}
        active_lock = asyncio.Lock()
    
        desired_ports: Set[int] = set()
    
        async def open_one_port(p: int) -> None:
            async with active_lock:
                if p in active_ports:
                    return
    
                async def on_user(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                    await _with_session_limit(ir_handle_user(reader, writer, p, pool))
    
                try:
                    server = await asyncio.start_server(
                        on_user,
                        host=T.ir_bind_host,
                        port=p,
                        backlog=T.backlog_ports,
                        reuse_address=True,
                    )
                except Exception as e:
                    log.warning("[IR] Cannot open port %d: %s", p, e)
                    return
    
                active_ports[p] = server
                log.info("[IR] Port Active: %d", p)
    
        async def apply_desired_ports(ports: Set[int]) -> None:
            # AutoSync sends the full desired set each interval.
            ports = set(int(p) for p in ports if 1 <= int(p) <= 65535)
            ports.discard(cfg.bridge_port)
            ports.discard(cfg.sync_port)
    
            async with active_lock:
                # Open newly desired ports
                to_open = sorted(p for p in ports if p not in active_ports)
                # Close ports no longer desired
                to_close = sorted(p for p in active_ports.keys() if p not in ports)
    
            for p in to_open:
                await open_one_port(p)
    
            if to_close:
                async with active_lock:
                    for p in to_close:
                        srv = active_ports.pop(p, None)
                        if srv is None:
                            continue
                        try:
                            srv.close()
                        except Exception:
                            pass
                        log.info("[IR] Port Closed: %d", p)
    
            desired_ports.clear()
            desired_ports.update(ports)
    
        tasks: List[asyncio.Task] = []
        tasks.append(asyncio.create_task(ir_accept_bridge(cfg, pool)))
        tasks.append(asyncio.create_task(pool_pinger()))
        tasks.append(asyncio.create_task(pool_recycler()))
    
        if cfg.auto_sync:
            tasks.append(asyncio.create_task(ir_sync_listener(cfg, apply_desired_ports)))
        else:
            for p in cfg.manual_ports:
                await open_one_port(p)
            log.info("[IR] Manual ports opened: %s", ",".join(map(str, cfg.manual_ports)) or "(none)")
    
        async def pool_recycler() -> None:
            while not stop.is_set():
                try:
                    removed = await pool.recycle_stale()
                    if removed:
                        log.debug("[IR] Recycled %d stale pool conns", removed)
                except Exception:
                    pass
                await asyncio.sleep(max(5.0, min(30.0, T.pool_max_age / 2)))
    
        tasks.append(asyncio.create_task(_supervise_task("IR:recycler", stop, pool_recycler)))
    
        log.info(
            "[IR] Running | bridge=%d sync=%d pool=%d autoSync=%s",
            cfg.bridge_port,
            cfg.sync_port,
            cfg.pool_size,
            cfg.auto_sync,
        )
    
        await stop.wait()
    
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    
        async with active_lock:
            for srv in active_ports.values():
                srv.close()
            await asyncio.gather(*(srv.wait_closed() for srv in active_ports.values()), return_exceptions=True)
    
    
    # ------------------------- stdin-driven interface -------------------------
    
    def read_line(prompt: Optional[str] = None) -> str:
        if prompt:
            print(prompt, end="", flush=True)
        s = sys.stdin.readline()
        if not s:
            return ""
        return s.strip()
    
    
    
    # ------------------------- Token auth -------------------------
    
    def _parse_ports_csv(csv: str) -> List[int]:
        ports: List[int] = []
        for part in (csv or "").split(","):
            part = part.strip()
            if not part:
                continue
            try:
                p = int(part)
            except Exception:
                continue
            if 1 <= p <= 65535:
                ports.append(p)
    
        # de-dup but preserve order
        seen: Set[int] = set()
        out: List[int] = []
        for p in ports:
            if p in seen:
                continue
            seen.add(p)
            out.append(p)
        return out
    
    
def main() -> None:
    _setup_logging()
    _bump_nofile(_env_int("PAHLAVI_NOFILE_TARGET", 65535))

    # expected input order (from your shell wrapper):
    # EU: 1, IRAN_IP, BRIDGE, SYNC, EU_AUTOSYNC(y/n)
    # IR: 2, BRIDGE, SYNC, y|n, [PORTS if n]
    choice = read_line()
    if choice not in ("1", "2"):
        print("Invalid mode selection.")
        sys.exit(1)

    if choice == "1":
        iran_ip = read_line() or "127.0.0.1"
        bridge = int(read_line() or "7000")
        sync = int(read_line() or "7001")

        autosync_line = read_line()
        if not autosync_line and sys.stdin.isatty():
            autosync_line = (input("Enable AutoSync (EU -> IR port sync)? [Y/n]: ") or "y").strip()
        enable_autosync = (autosync_line or "y").lower().startswith("y")

        pool = auto_pool_size("eu")
        try:
            nofile = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        except Exception:
            nofile = -1
        log.info(
            "[AUTO] role=EU nofile=%s pool=%s autosync=%s (override: PAHLAVI_POOL)",
            nofile,
            pool,
            enable_autosync,
        )
        asyncio.run(
            run_eu(
                EUConfig(
                    iran_ip=iran_ip,
                    bridge_port=bridge,
                    sync_port=sync,
                    pool_size=pool,
                    enable_autosync=enable_autosync,
                )
            )
        )
    else:
        bridge = int(read_line() or "7000")
        sync = int(read_line() or "7001")
        yn = (read_line() or "y").lower()
        pool = auto_pool_size("ir")
        try:
            nofile = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        except Exception:
            nofile = -1
        log.info("[AUTO] role=IR nofile=%s pool=%s (override: PAHLAVI_POOL)", nofile, pool)

        if yn == "y":
            cfg = IRConfig(
                bridge_port=bridge,
                sync_port=sync,
                pool_size=pool,
                auto_sync=True,
                manual_ports=[],
            )
        else:
            ports_csv = read_line()
            cfg = IRConfig(
                bridge_port=bridge,
                sync_port=sync,
                pool_size=pool,
                auto_sync=False,
                manual_ports=_parse_ports_csv(ports_csv),
            )

        asyncio.run(run_ir(cfg))


if __name__ == "__main__":
    main()
