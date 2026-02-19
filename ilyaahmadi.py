#!/usr/bin/env python3
import os, sys, time, socket, struct, threading, subprocess, re
from queue import Queue, Empty

# --------- Tunables ----------
DIAL_TIMEOUT = 5
KEEPALIVE_SECS = 20
SOCKBUF = 8 * 1024 * 1024
BUF_COPY = 256 * 1024
POOL_WAIT = 5
SYNC_INTERVAL = 3

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
        while True:
            try:
                conn = dial_tcp(iran_ip, bridge_port)
                # wait for 2-byte target port
                hdr = conn.recv(2)
                if len(hdr) != 2:
                    conn.close(); continue
                (target_port,) = struct.unpack("!H", hdr)
                local = dial_tcp("127.0.0.1", target_port)
                bridge(conn, local)
            except Exception:
                time.sleep(0.2)

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
            c, _ = srv.accept()
            tune_tcp(c)
            try:
                pool.put(c, block=False)
            except Exception:
                try: c.close()
                except Exception: pass

    def handle_user(user_sock: socket.socket, target_port: int):
        tune_tcp(user_sock)
        try:
            europe = pool.get(timeout=POOL_WAIT)
        except Empty:
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
                u, _ = srv.accept()
                threading.Thread(target=handle_user, args=(u,p), daemon=True).start()
        threading.Thread(target=accept_users, daemon=True).start()

    def sync_listener():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", sync_port))
        srv.listen(1024)
        print(f"[IR] Sync listening on {sync_port} (AutoSync)")
        while True:
            c, _ = srv.accept()
            def handle_sync(conn):
                try:
                    while True:
                        h = conn.recv(1)
                        if not h:
                            break
                        count = h[0]
                        for _ in range(count):
                            pd = conn.recv(2)
                            if len(pd) != 2:
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
        eu_mode(iran_ip, bridge, sync, pool_size=800)
    else:
        bridge = int(read_line() or "7000")
        sync = int(read_line() or "7001")
        yn = (read_line() or "y").lower()
        if yn == "y":
            ir_mode(bridge, sync, pool_size=800, auto_sync=True, manual_ports_csv="")
        else:
            ports = read_line()
            ir_mode(bridge, sync, pool_size=800, auto_sync=False, manual_ports_csv=ports)

if __name__ == "__main__":
    main()
