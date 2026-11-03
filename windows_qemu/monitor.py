#!/usr/bin/env python3
"""Send HMP commands to the running VM's monitor socket, e.g.
   sudo ./monitor.py 'info status' 'screendump /tmp/win.ppm' system_reset"""
import os, re, socket, sys, time

sock = os.environ.get("MONITOR_SOCK", os.path.join(os.path.dirname(os.path.abspath(__file__)), "state", "monitor.sock"))
s = socket.socket(socket.AF_UNIX); s.connect(sock); s.settimeout(1.0)

def drain():
    out = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk: break
            out += chunk
    except socket.timeout:
        pass
    return out.decode(errors="replace")

drain()  # banner
for cmd in sys.argv[1:]:
    s.sendall((cmd + "\n").encode()); time.sleep(0.3)
    # QEMU echoes the typed command (with cursor escapes) on the first line, then the reply, then "(qemu)".
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", drain().replace("\r", ""))
    lines = [l for l in text.split("\n")[1:] if l.strip() and not l.startswith("(qemu)")]
    if lines: print("\n".join(lines))
