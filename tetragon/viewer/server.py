#!/usr/bin/env python3
"""Minimal local web viewer for Tetragon's JSON event log (stdlib only).

Serves index.html and streams log lines to the browser with Server-Sent
Events, following the file across Tetragon's log rotation.
"""
import argparse
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
BACKLOG_LINES = 1000
BACKLOG_BYTES = 4 * 1024 * 1024
HEARTBEAT_SECS = 15


def follow(path):
    """Yield the last BACKLOG_LINES lines, then new lines as they arrive.

    Yields None when idle so the caller can send heartbeats.
    """
    f, ino, buf, backlog = None, None, b"", True
    while True:
        if f is None:
            try:
                f = open(path, "rb")
            except FileNotFoundError:
                yield None
                time.sleep(1)
                continue
            st = os.fstat(f.fileno())
            ino = st.st_ino
            if backlog:
                f.seek(max(0, st.st_size - BACKLOG_BYTES))
                lines = f.read().split(b"\n")
                buf = lines.pop()  # incomplete last line (usually b"")
                if st.st_size > BACKLOG_BYTES:
                    lines = lines[1:]  # first line is probably cut
                for line in lines[-BACKLOG_LINES:]:
                    yield line
                backlog = False

        chunk = f.readline()
        if chunk:
            buf += chunk
            if buf.endswith(b"\n"):
                yield buf[:-1]
                buf = b""
            continue

        # At EOF: reopen if the file was rotated or truncated.
        try:
            st = os.stat(path)
        except FileNotFoundError:
            st = None
        if st is None or st.st_ino != ino or st.st_size < f.tell():
            f.close()
            f, buf = None, b""
            continue
        yield None
        time.sleep(0.25)


class Handler(BaseHTTPRequestHandler):
    log_path = None
    allowed_hosts = set()

    def log_message(self, *args):
        pass

    def do_GET(self):
        # Reject other Host headers to block DNS-rebinding from web pages.
        if self.headers.get("Host", "") not in self.allowed_hosts:
            self.send_error(403)
            return
        if self.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/events":
            self.stream()
        else:
            self.send_error(404)

    def stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        try:
            # Tell the page to clear, so reconnects don't duplicate rows.
            self.wfile.write(b"event: reset\ndata: \n\n")
            last = time.monotonic()
            for line in follow(self.log_path):
                now = time.monotonic()
                if line:
                    self.wfile.write(b"data: " + line + b"\n\n")
                    last = now
                elif now - last >= HEARTBEAT_SECS:
                    self.wfile.write(b": ping\n\n")
                    last = now
                else:
                    continue
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--log", default="/var/log/tetragon/tetragon.log")
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8099)
    args = p.parse_args()

    Handler.log_path = args.log
    Handler.allowed_hosts = {
        f"{h}:{args.port}" for h in ("127.0.0.1", "localhost", args.bind)
    }
    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    srv.daemon_threads = True
    print(f"Tetragon viewer on http://{args.bind}:{args.port} (log: {args.log})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
