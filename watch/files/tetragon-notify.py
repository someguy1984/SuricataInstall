#!/usr/bin/env python3
"""Turn Tetragon's journal copy of policy hits into desktop notifications.

Reads the JSON events that tetragon-alerts.service writes to the journal (on stdin, from
`journalctl -t tetragon-alerts -f`) and calls ips-notify for the ones worth interrupting
someone for. Nothing is filtered out of the journal or the event log by this: the ignore
list only decides what pops up on screen.

Each event is reduced to one line,

    POLICY FUNCTION BINARY DETAIL <- PARENT

for example

    sensitive-files security_file_permission /usr/bin/cat /home/j/.ssh/id_ed25519 <- /usr/bin/bash

(a script is named by its own path, not its interpreter's) and dropped if any pattern
in the ignore file matches that line (Python regular
expressions, one per line, searched anywhere in it). Run with --print to see the lines
for the events on stdin without notifying, which is how to write a new pattern (needs
sudo: the ignore list is root-only, and without it nothing is marked as dropped):

    sudo journalctl -t tetragon-alerts --since -1d -o cat | sudo tetragon-notify.py --print | sort | uniq -c | sort -rn

Two limits keep a noisy program from flooding the screen: the same policy and binary
notify once per --repeat seconds, and at most --burst notifications are shown per
--window seconds (one more then says that the rest were held back, and the next
notification after the burst says which policies they were).

Tampering with the watchers themselves (ALWAYS below) is not subject to either: a
different file is a different alert, and a burst of other alerts does not hold it back.
It has a limit of its own, four times as high, so a reinstall cannot bury the screen.
"""
import argparse
import json
import re
import subprocess
import sys
import time

# Tampering with Tetragon or with the IPS: see the module comment
ALWAYS = {"tetragon-tamper", "stack-tamper"}
# Worth knowing, not worth a notification that stays on screen until dismissed
QUIET = {"tcp-listen", "device-access"}


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
    if parent.get("binary"):
        summary += f' <- {parent["binary"]}'
    body = [f'{binary} (pid {proc.get("pid", "?")}, uid {proc.get("uid", "?")})']
    if extra:
        body.append(extra[:300])
    if parent.get("binary"):
        body.append(f'started by {parent["binary"]} {" ".join(str(parent.get("arguments", "")).split())}'[:200])
    body.append(f"journalctl -t tetragon-alerts | grep {policy}")
    return summary, f"Tetragon: {what}", "\n".join(body), policy, binary


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
    last = {}                        # dedup key -> time of its last notification
    sent = {False: [], True: []}     # times of recent notifications: ordinary, ALWAYS
    held = {}                        # policy -> how many were held back in this burst
    announced = False                # the "holding back" notice has been shown for it

    for line in sys.stdin:
        try:
            event = json.loads(line)
            described = describe(event) if isinstance(event, dict) else None
        except Exception as e:       # one odd event must not end the notifications
            print(f"skipped an event that could not be read: {e!r}", file=sys.stderr, flush=True)
            continue
        if not described:
            continue
        summary, title, body, policy, binary = described
        ignored = any(r.search(summary) for r in ignores)
        if args.print:
            print(("- " if ignored else "  ") + summary, flush=True)
            continue
        if ignored:
            continue
        now = time.monotonic()
        always = policy in ALWAYS
        key = (policy, summary) if always else (policy, binary)
        if now - last.get(key, -1e9) < args.repeat:
            continue
        for kind in sent:
            sent[kind] = [t for t in sent[kind] if now - t < args.window]
        if len(sent[always]) >= args.burst * (4 if always else 1):
            held[policy] = held.get(policy, 0) + 1
            if not announced:
                announced = True
                subprocess.run([args.notify, "normal", "Tetragon: more alerts are being held back",
                                f"More than {args.burst} in {int(args.window / 60)} minutes. "
                                "They are all in the journal: journalctl -t tetragon-alerts"])
            continue
        if held and len(sent[False]) < args.burst:
            # The burst is over: say what did not make it to the screen
            what = ", ".join(f"{n} x {name}" for name, n in sorted(held.items()))
            subprocess.run([args.notify, "normal", "Tetragon: alerts held back during the last burst",
                            f"{what}. They are all in the journal: journalctl -t tetragon-alerts"])
            held, announced = {}, False
        last[key] = now
        sent[always].append(now)
        if len(last) > 5000:  # forget the oldest; nothing else bounds this
            for old in sorted(last, key=last.get)[:1000]:
                del last[old]
        subprocess.run([args.notify, "normal" if policy in QUIET else "critical", title, body])


if __name__ == "__main__":
    try:
        main()
    except (BrokenPipeError, KeyboardInterrupt):
        pass
