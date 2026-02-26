#!/usr/bin/env python3
import os, sys, time, socket, struct, threading, subprocess, re, resource
from queue import Queue, Empty
from typing import Optional

# --------- Tunables ----------
DIAL_TIMEOUT = 5
KEEPALIVE_SECS = 20
SOCKBUF = 8 * 1024 * 1024
BUF_COPY = 256 * 1024
POOL_WAIT = 5
SYNC_INTERVAL = 3

# --------- Auto pool sizing ----------
def auto_pool_size(role: str = "ir") -> int:
    """Pick a safe default pool size based on process FD limit + RAM.
    Can be overridden with env var PAHLAVI_POOL (positive int).
    """
    # Allow explicit override
    try:
        env_pool = int(os.environ.get("PAHLAVI_POOL", "0"))
        if env_pool > 0:
            return env_pool
    except Exception:
        pass

    # File descriptor limit for this process
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        nofile = soft if soft and soft > 0 else 1024
    except Exception:
        nofile = 1024

    # Total RAM (best-effort)
    mem_mb = 0
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_kb = int(line.split()[1])
                    mem_mb = mem_kb // 1024
                    break
    except Exception:
        mem_mb = 0

    # Reserve room for listeners, logs, timewait bursts, and user sockets
    reserve = 500
    fd_budget = max(0, nofile - reserve)

    # IR side tends to have more concurrent user sockets; be more conservative
    frac = 0.22 if role.lower().startswith("ir") else 0.30
    fd_based = int(fd_budget * frac)

    # RAM cap (rough): allow ~250 pool per 1GB
    ram_based = int((mem_mb / 1024) * 250) if mem_mb else 500

    pool = min(fd_based, ram_based)

    # Clamp to sane bounds
    if pool < 100:
        pool = 100
    if pool > 2000:
        pool = 2000
    return pool

def is_socket_alive(s: socket.socket) -> bool:
    """Best-effort check to avoid using dead sockets from the pool."""
    try:
        s.setblocking(False)
        try:
            data = s.recv(1, socket.MSG_PEEK)
            if data == b"":
                return False
        except BlockingIOError:
            return True
        except Exception:
            # If we can't peek, assume it's OK; actual send will validate
            return True
        finally:
            s.setblocking(True)
        return True
    except Exception:
        return False

def tune_tcp(sock: socket.socket):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKBUF)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKBUF)
    except Exception:
        pass
    # keepalive
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Linux specific options
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_SECS)
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_SECS)
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except Exception:
        pass

def dial_tcp(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tune_tcp(s)
    s.settimeout(DIAL_TIMEOUT)
    s.connect((host, port))
    s.settimeout(None)
    return s


def recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    """Receive exactly n bytes or return None if the connection closes."""
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)

def pipe(a: socket.socket, b: socket.socket):
    buf = bytearray(BUF_COPY)
    try:
        while True:
            n = a.recv_into(buf)
            if n <= 0:
                break
            b.sendall(memoryview(buf)[:n])
    except Exception:
        pass
    finally:
        try: a.shutdown(socket.SHUT_RD)
        except Exception: pass
        try: b.shutdown(socket.SHUT_WR)
        except Exception: pass

def bridge(a: socket.socket, b: socket.socket):
    t1 = threading.Thread(target=pipe, args=(a,b), daemon=True)
    t2 = threading.Thread(target=pipe, args=(b,a), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    try: a.close()
    except Exception: pass
    try: b.close()
    except Exception: pass

# --------- EU: detect listening TCP ports (like ss) ----------
_port_re = re.compile(r":(\d+)$")
def get_listen_ports(exclude_bridge, exclude_sync):
    try:
        out = subprocess.check_output(["bash","-lc","ss -lntp | awk '{print $4}'"], stderr=subprocess.DEVNULL).decode()
    except Exception:
        return []
    ports = set()
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln: 
            continue
        m = _port_re.search(ln)
        if not m:
            continue
        p = int(m.group(1))
        if p in (exclude_bridge, exclude_sync):
            continue
        if 1 <= p <= 65535:
            ports.add(p)
    return sorted(ports)

# --------- EU mode ----------
def eu_mode(iran_ip, bridge_port, sync_port, pool_size):
    def port_sync_loop():
        while True:
            try:
                c = dial_tcp(iran_ip, sync_port)
            except Exception:
                time.sleep(SYNC_INTERVAL); continue
            try:
                while True:
                    ports = get_listen_ports(bridge_port, sync_port)[:255]
                    payload = bytes([len(ports)]) + b"".join(struct.pack("!H", p) for p in ports)
                    c.settimeout(2)
                    c.sendall(payload)
                    c.settimeout(None)
                    time.sleep(SYNC_INTERVAL)
            except Exception:
                try: c.close()
                except Exception: pass
                time.sleep(SYNC_INTERVAL)

    def reverse_link_worker():
        delay = 0.2
        while True:
            try:
                conn = dial_tcp(iran_ip, bridge_port)
                # wait for 2-byte target port
                hdr = recv_exact(conn, 2)
                if not hdr:
                    conn.close(); continue
                (target_port,) = struct.unpack("!H", hdr)
                local = dial_tcp("127.0.0.1", target_port)
                bridge(conn, local)
                delay = 0.2
            except Exception:
                time.sleep(delay)
                delay = min(delay * 2, 5.0)

    threading.Thread(target=port_sync_loop, daemon=True).start()
    for _ in range(pool_size):
        threading.Thread(target=reverse_link_worker, daemon=True).start()

    print(f"[EU] Running | IRAN={iran_ip} bridge={bridge_port} sync={sync_port} pool={pool_size}")
    while True:
        time.sleep(3600)

# --------- IR mode ----------
def ir_mode(bridge_port, sync_port, pool_size, auto_sync, manual_ports_csv):
    pool = Queue(maxsize=pool_size * 2)
    active = {}
    active_lock = threading.Lock()

    def accept_bridge():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", bridge_port))
        srv.listen(16384)
        print(f"[IR] Bridge listening on {bridge_port}")
        while True:
            try:
                c, _ = srv.accept()
            except OSError as e:
                print(f"[IR] sync_listener error: {e}")
                time.sleep(0.2)
                continue
            tune_tcp(c)
            try:
                pool.put(c, block=False)
            except Exception:
                try: c.close()
                except Exception: pass

    def handle_user(user_sock: socket.socket, target_port: int):
        tune_tcp(user_sock)
        deadline = time.time() + POOL_WAIT
        europe = None
        while time.time() < deadline:
            try:
                cand = pool.get(timeout=max(0.1, deadline - time.time()))
            except Empty:
                break
            if is_socket_alive(cand):
                europe = cand
                break
            try: cand.close()
            except Exception: pass
        if europe is None:
            try: user_sock.close()
            except Exception: pass
            return
        try:
            europe.settimeout(2)
            europe.sendall(struct.pack("!H", target_port))
            europe.settimeout(None)
        except Exception:
            try: user_sock.close()
            except Exception: pass
            try: europe.close()
            except Exception: pass
            return
        bridge(user_sock, europe)

    def open_port(p: int):
        with active_lock:
            if p in active:
                return
            active[p] = True

        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", p))
            srv.listen(16384)
        except Exception as e:
            with active_lock:
                active.pop(p, None)
            print(f"[IR] Cannot open port {p}: {e}")
            return

        print(f"[IR] Port Active: {p}")

        def accept_users():
            while True:
                try:
                    u, _ = srv.accept()
                except OSError as e:
                    print(f"[IR] accept_users({p}) error: {e}")
                    time.sleep(0.2)
                    continue
                try:
                    threading.Thread(target=handle_user, args=(u,p), daemon=True).start()
                except Exception as e:
                    print(f"[IR] spawn thread error: {e}")
                    try: u.close()
                    except Exception: pass
        threading.Thread(target=accept_users, daemon=True).start()

    def sync_listener():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", sync_port))
        srv.listen(1024)
        print(f"[IR] Sync listening on {sync_port} (AutoSync)")
        while True:
            try:
                c, _ = srv.accept()
            except OSError as e:
                print(f"[IR] accept_bridge error: {e}")
                time.sleep(0.2)
                continue
            def handle_sync(conn):
                try:
                    while True:
                        h = recv_exact(conn, 1)
                        if not h:
                            break
                        count = h[0]
                        for _ in range(count):
                            pd = recv_exact(conn, 2)
                            if not pd:
                                return
                            (p,) = struct.unpack("!H", pd)
                            open_port(p)
                except Exception:
                    pass
                finally:
                    try: conn.close()
                    except Exception: pass
            threading.Thread(target=handle_sync, args=(c,), daemon=True).start()

    threading.Thread(target=accept_bridge, daemon=True).start()

    if auto_sync:
        threading.Thread(target=sync_listener, daemon=True).start()
    else:
        ports = []
        if manual_ports_csv.strip():
            for part in manual_ports_csv.split(","):
                part = part.strip()
                if not part: 
                    continue
                try:
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports.append(p)
                except Exception:
                    pass
        for p in ports:
            open_port(p)
        print("[IR] Manual ports opened.")

    print(f"[IR] Running | bridge={bridge_port} sync={sync_port} pool={pool_size} autoSync={auto_sync}")
    while True:
        time.sleep(3600)

# --------- Simple stdin-driven menu (works with your .sh printf feeding) ----------
def read_line(prompt=None):
    if prompt:
        print(prompt, end="", flush=True)
    s = sys.stdin.readline()
    if not s:
        return ""
    return s.strip()

def main():
    # expected input order (from your shell wrapper):
    # EU: 1, IRAN_IP, BRIDGE, SYNC
    # IR: 2, BRIDGE, SYNC, y|n, [PORTS if n]
    choice = read_line()
    if choice not in ("1","2"):
        print("Invalid mode selection.")
        sys.exit(1)

    if choice == "1":
        iran_ip = read_line()
        bridge = int(read_line() or "7000")
        sync = int(read_line() or "7001")
        pool = auto_pool_size("eu")
        try:
            nofile = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        except Exception:
            nofile = -1
        print(f"[AUTO] role=EU nofile={nofile} pool={pool} (override: PAHLAVI_POOL)")
        eu_mode(iran_ip, bridge, sync, pool_size=pool)
    else:
        bridge = int(read_line() or "7000")
        sync = int(read_line() or "7001")
        yn = (read_line() or "y").lower()
        if yn == "y":
            pool = auto_pool_size("ir")
            try:
                nofile = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            except Exception:
                nofile = -1
            print(f"[AUTO] role=IR nofile={nofile} pool={pool} (override: PAHLAVI_POOL)")
            ir_mode(bridge, sync, pool_size=pool, auto_sync=True, manual_ports_csv="")
        else:
            ports = read_line()
            pool = auto_pool_size("ir")
            try:
                nofile = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            except Exception:
                nofile = -1
            print(f"[AUTO] role=IR nofile={nofile} pool={pool} (override: PAHLAVI_POOL)")
            ir_mode(bridge, sync, pool_size=pool, auto_sync=False, manual_ports_csv=ports)

if __name__ == "__main__":
    main()
