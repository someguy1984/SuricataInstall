#!/usr/bin/env python3
"""Turn Tetragon's journal copy of policy hits into desktop notifications.

Reads the JSON events that tetragon-alerts.service writes to the journal (on stdin, from
`journalctl -t tetragon-alerts -f`) and calls ips-notify for the ones worth interrupting
someone for. Nothing is filtered out of the journal or the event log by this: the ignore
list only decides what pops up on screen.

Each event is reduced to one line,

    POLICY FUNCTION BINARY DETAIL

for example

    sensitive-files security_file_permission /usr/bin/cat /home/j/.ssh/id_ed25519

and dropped if any pattern in the ignore file matches that line (Python regular
expressions, one per line, searched anywhere in it). Run with --print to see the lines
for the events on stdin without notifying, which is how to write a new pattern:

    journalctl -t tetragon-alerts --since -1d -o cat | tetragon-notify.py --print | sort | uniq -c | sort -rn

Two limits keep a noisy program from flooding the screen: the same policy and binary
notify once per --repeat seconds, and at most --burst notifications are shown per
--window seconds (one more then says that the rest were held back).
"""
import argparse
import json
import re
import subprocess
import sys
import time


def detail(args):
    """The interesting part of a kprobe's arguments: paths, names and addresses."""
    out = []
    for arg in args or []:
        for key, val in arg.items():
            if key == "label":
                continue
            if isinstance(val, dict):
                if "path" in val:
                    val = val["path"]
                elif "saddr" in val or "daddr" in val:
                    val = f'{val.get("saddr", "")}:{val.get("sport", "")}'
                elif "name" in val:
                    val = val["name"]
                else:
                    continue
            elif key in ("int_arg", "uint_arg", "size_arg", "long_arg") and "label" not in arg:
                continue  # access masks and the like: no use to a reader
            text = " ".join(str(val).split())
            if text:
                out.append(f'{arg["label"]}={text}' if "label" in arg else text)
    return " ".join(out)


def describe(event):
    """(summary line, title, body) for one event, or None if it isn't one we report."""
    if "process_kprobe" in event:
        k = event["process_kprobe"]
        policy, function = k.get("policy_name", "?"), k.get("function_name", "?")
        what = k.get("message") or f"{policy}: {function}"
        extra = detail(k.get("args"))
    elif "process_exec" in event:
        k = event["process_exec"]
        policy, function = "fileless-exec", "exec"
        what = "Program executed with no file behind it (memfd or deleted)"
        extra = " ".join(str(k.get("process", {}).get("arguments", "")).split())
    else:
        return None
    proc, parent = k.get("process", {}), k.get("parent", {})
    binary = proc.get("binary", "?")
    summary = " ".join(x for x in (policy, function, binary, extra) if x)
    body = [f'{binary} (pid {proc.get("pid", "?")}, uid {proc.get("uid", "?")})']
    if extra:
        body.append(extra[:300])
    if parent.get("binary"):
        body.append(f'started by {parent["binary"]} {" ".join(str(parent.get("arguments", "")).split())}'[:200])
    body.append(f"journalctl -t tetragon-alerts | grep {policy}")
    return summary, f"Tetragon: {what}", "\n".join(body), (policy, binary)


def load_ignores(path):
    patterns = []
    try:
        with open(path) as f:
            for n, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    patterns.append(re.compile(line))
                except re.error as e:
                    print(f"{path}:{n}: bad pattern ignored: {e}", file=sys.stderr, flush=True)
    except OSError as e:
        print(f"no ignore list ({e}); every policy hit will notify", file=sys.stderr, flush=True)
    return patterns


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ignore", default="/etc/ips-watch/tetragon-ignore.conf")
    p.add_argument("--notify", default="/usr/local/sbin/ips-notify")
    p.add_argument("--repeat", type=float, default=600, help="seconds before the same policy+binary notifies again")
    p.add_argument("--burst", type=int, default=5, help="notifications allowed per window")
    p.add_argument("--window", type=float, default=300, help="length of the window in seconds")
    p.add_argument("--print", action="store_true", help="print each event's summary line (with '-' in front "
                   "if the ignore list drops it) instead of notifying")
    args = p.parse_args()

    ignores = load_ignores(args.ignore)
    last = {}     # (policy, binary) -> time of its last notification
    sent = []     # times of recent notifications, for the burst limit
    held = False  # the "holding back" notice has been shown for the current burst

    for line in sys.stdin:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        described = describe(event) if isinstance(event, dict) else None
        if not described:
            continue
        summary, title, body, key = described
        ignored = any(r.search(summary) for r in ignores)
        if args.print:
            print(("- " if ignored else "  ") + summary, flush=True)
            continue
        if ignored:
            continue
        now = time.monotonic()
        if now - last.get(key, -1e9) < args.repeat:
            continue
        sent = [t for t in sent if now - t < args.window]
        if len(sent) >= args.burst:
            if not held:
                held = True
                subprocess.run([args.notify, "normal", "Tetragon: more alerts are being held back",
                                f"More than {args.burst} in {int(args.window / 60)} minutes. "
                                "They are all in the journal: journalctl -t tetragon-alerts"])
            continue
        held = False
        last[key] = now
        sent.append(now)
        if len(last) > 5000:  # forget the oldest; nothing else bounds this
            for old in sorted(last, key=last.get)[:1000]:
                del last[old]
        subprocess.run([args.notify, "critical", title, body])


if __name__ == "__main__":
    try:
        main()
    except (BrokenPipeError, KeyboardInterrupt):
        pass
