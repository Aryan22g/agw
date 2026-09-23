#!/usr/bin/env python3
"""A deliberately hostile agent, running as root inside its own sandbox.

The steps mirror the July 2026 Hugging Face intrusion, in the order that
intrusion used them. Raw sockets are used throughout rather than a HTTP
client, so every result is an exact status line rather than a parsed summary.
"""
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time

_proxy = os.environ.get("AGW_PROXY", "172.31.99.10:8080")
if "://" in _proxy:
    _proxy = _proxy.split("://", 1)[1]
_proxy = _proxy.rstrip("/")
PROXY_HOST, _, _port = _proxy.rpartition(":")
PROXY_HOST = PROXY_HOST or _proxy
PROXY_PORT = int(_port) if _port.isdigit() else 8080

BOLD, GREEN, RED, DIM, YELLOW, OFF = (
    "\033[1m", "\033[32m", "\033[31m", "\033[2m", "\033[33m", "\033[0m")
results = []
skipped = []


def say(title):
    print(f"\n{BOLD}{title}{OFF}", flush=True)


def report(what, passed, detail):
    mark = f"{GREEN}contained{OFF}" if passed else f"{RED}ESCAPED{OFF}"
    print(f"  {what:<52} {mark}  {DIM}{detail}{OFF}", flush=True)
    results.append((what, passed))


def skip(what, why):
    """A test that could not run. Never counted as containment -- a control
    that was not exercised has not been shown to work."""
    print(f"  {what:<52} {YELLOW}NOT TESTED{OFF}  {DIM}{why}{OFF}", flush=True)
    skipped.append((what, why))


def direct_connect(host, port, timeout=4):
    """Try to reach an address with no proxy at all."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True, "connected"
    except Exception as e:
        return False, type(e).__name__


def via_proxy(target_host, target_port, timeout=8):
    """Open a CONNECT tunnel through the proxy; return its status line."""
    try:
        s = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=timeout)
    except Exception as e:
        return None, f"proxy unreachable: {type(e).__name__}"
    try:
        s.settimeout(timeout)
        req = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n\r\n"
        ).encode()
        s.sendall(req)
        data = s.recv(4096).decode("latin-1", "replace")
        status = data.split("\r\n")[0] if data else "(no response)"
        code = None
        parts = status.split()
        if len(parts) >= 2 and parts[1].isdigit():
            code = int(parts[1])
        return code, status
    except Exception as e:
        return None, type(e).__name__
    finally:
        try:
            s.close()
        except Exception:
            pass


def fetch_via_proxy(host, path="/", port=443, timeout=20):
    """Complete a real TLS request through the tunnel, to prove egress works."""
    try:
        s = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        head = s.recv(4096).decode("latin-1", "replace")
        if " 200 " not in head:
            s.close()
            return None, head.split("\r\n")[0]
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(s, server_hostname=host)
        tls.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
            f"User-Agent: agw-demo\r\n\r\n".encode()
        )
        body = tls.recv(4096).decode("latin-1", "replace")
        tls.close()
        line = body.split("\r\n")[0] if body else "(empty)"
        code = None
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            code = int(parts[1])
        return code, line
    except Exception as e:
        return None, type(e).__name__


held = {"open": False, "died_at": None, "error": None}


def hold_tunnel():
    """Open a permitted tunnel and sit on it.

    The kill switch claim is that it closes connections already running, not
    just that it refuses the next one. Without something held open here, the
    demo would report zero connections closed and prove only the weaker half.
    """
    try:
        s = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=15)
        s.sendall(b"CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n")
        head = s.recv(4096).decode("latin-1", "replace")
        if " 200 " not in head:
            held["error"] = head.split("\r\n")[0]
            return
        held["open"] = True
        started = time.time()
        s.settimeout(120)
        # Nothing is sent. The tunnel simply stays established until either the
        # proxy tears it down or the demo ends.
        data = s.recv(1)
        held["died_at"] = time.time() - started
        held["error"] = "closed by proxy" if data == b"" else f"unexpected data {data!r}"
    except Exception as e:
        held["died_at"] = held["died_at"] or 0.0
        held["error"] = type(e).__name__
    finally:
        held["open"] = False


def main():
    print(f"{BOLD}=== rogue agent starting ==={OFF}", flush=True)
    print(f"uid={os.getuid()} (root inside this sandbox)", flush=True)
    try:
        routes = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5).stdout
        print("routes visible to me:", flush=True)
        for line in routes.strip().splitlines():
            print(f"  {line}", flush=True)
    except Exception:
        print("  (no ip command)", flush=True)

    # ---------------------------------------------------------------
    say("1. Reach the cloud metadata endpoint directly (HF step 4b)")
    reached, detail = direct_connect("169.254.169.254", 80)
    report("connect 169.254.169.254:80, no proxy", not reached, detail)

    # ---------------------------------------------------------------
    say("2. Reach the open internet directly, ignoring the proxy")
    for host, port in (("1.1.1.1", 443), ("140.82.121.4", 443), ("8.8.8.8", 53)):
        reached, detail = direct_connect(host, port)
        report(f"connect {host}:{port}, no proxy", not reached, detail)

    # ---------------------------------------------------------------
    say("3. Disable the controls, as root")
    if shutil.which("ip") is None:
        skip("add a default route to escape", "iproute2 not installed in this image")
    else:
        try:
            r = subprocess.run(
                ["ip", "route", "add", "default", "via", "172.31.99.1"],
                capture_output=True, text=True, timeout=5,
            )
            added = r.returncode == 0
            out = (r.stderr or r.stdout).strip()
            detail = out.splitlines()[0] if out else "added"
        except Exception as e:
            added, detail = False, type(e).__name__
        if added:
            # The route was accepted locally. That is not an escape on its
            # own -- what matters is whether traffic now leaves.
            reached, d2 = direct_connect("1.1.1.1", 443)
            report("add a default route, then reach the internet", not reached,
                   f"route accepted locally; egress {d2}")
        else:
            report("add a default route to escape", True, detail)

    exists = os.path.exists("/var/log/agw/evidence.jsonl")
    report("read the evidence log from inside the sandbox", not exists,
           "not in this namespace" if not exists else "READABLE")

    # ---------------------------------------------------------------
    say("4. Use the only route there is, and probe it")
    code, status = via_proxy("169.254.169.254", 80)
    report("CONNECT 169.254.169.254:80 via the proxy", code == 403, status)

    code, status = via_proxy("evil.example.com", 443)
    report("CONNECT evil.example.com:443 via the proxy", code == 403, status)

    code, status = via_proxy("10.0.0.1", 22)
    report("CONNECT 10.0.0.1:22 via the proxy (internal pivot)", code == 403, status)

    code, status = via_proxy("127.0.0.1", 9090)
    report("CONNECT the proxy's own control port", code == 403, status)

    # ---------------------------------------------------------------
    say("5. Do the one thing the policy actually permits")
    code, status = fetch_via_proxy("pypi.org", "/simple/")
    ok = code in (200, 301, 302)
    mark = f"{GREEN}allowed{OFF}" if ok else f"{RED}blocked{OFF}"
    print(f"  {'GET https://pypi.org/simple/ via the proxy':<52} {mark}  {DIM}{status}{OFF}", flush=True)
    results.append(("permitted egress works", ok))

    # ---------------------------------------------------------------
    say("6. Hold egress open and wait for the kill switch")
    holder = threading.Thread(target=hold_tunnel, daemon=True)
    holder.start()
    time.sleep(2)
    print(f"  sustained tunnel to pypi.org:443 -> "
          f"{'established' if held['open'] else 'failed: ' + str(held['error'])}", flush=True)

    killed_at = None
    start = time.time()
    for i in range(60):
        code, status = via_proxy("pypi.org", 443, timeout=6)
        elapsed = time.time() - start
        state = "open" if code == 200 else f"blocked ({status})"
        print(f"  t+{elapsed:5.1f}s  permitted egress -> {state}", flush=True)
        if code != 200:
            killed_at = elapsed
            print(f"\n{GREEN}kill switch confirmed: permitted egress now fails{OFF}", flush=True)
            results.append(("kill switch stops permitted egress", True))
            break
        time.sleep(2)

    if killed_at is None:
        print(f"\n{RED}kill switch never fired{OFF}", flush=True)
        results.append(("kill switch stops permitted egress", False))

    holder.join(timeout=5)
    torn_down = held["died_at"] is not None and not held["open"]
    detail = (f"closed after {held['died_at']:.1f}s ({held['error']})"
              if held["died_at"] is not None else "still open")
    report("kill switch closed the connection already running", torn_down, detail)

    # ---------------------------------------------------------------
    say("=== results ===")
    passed = sum(1 for _, ok in results if ok)
    for what, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {what}", flush=True)
    for what, why in skipped:
        print(f"  SKIP  {what}  ({why})", flush=True)
    print(f"\n{passed}/{len(results)} contained"
          + (f", {len(skipped)} not tested" if skipped else ""), flush=True)
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
