#!/bin/bash
# Static checks for everything in the repo. Changes nothing and needs nothing installed
# beyond bash and python3; the optional tools are used when present and reported as skipped
# when not (shellcheck, PyYAML, systemd-analyze).
#
# Usage: tests/lint.sh SHELL-FILES... -- PYTHON-FILES...     (normally via: make lint)
set -uo pipefail

ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
cd "$ROOT" || exit 1

sh_files=() py_files=() in_py=0
for arg in "$@"; do
    if [[ $arg == -- ]]; then in_py=1; elif [[ $in_py -eq 1 ]]; then py_files+=("$arg"); else sh_files+=("$arg"); fi
done

FAIL=0
ok() { echo "  ok    $*"; }
bad() { echo "  FAIL  $*"; FAIL=1; }
skip() { echo "  skip  $*"; }

echo "== Shell syntax (bash -n)"
n=0
for f in "${sh_files[@]}"; do
    [[ -f $f ]] || { bad "$f is listed in the Makefile but does not exist"; continue; }
    if out=$(bash -n "$f" 2>&1); then n=$((n + 1)); else bad "$f: $out"; fi
done
ok "$n scripts parse"
# Every script in the repo should be on the list, or a new one silently goes unchecked
while IFS= read -r f; do
    printf '%s\n' "${sh_files[@]}" | grep -qxF -- "$f" || bad "$f is a shell script but is not in the Makefile's SH_FILES"
done < <(grep -rlE '^#!.*\b(ba)?sh\b' --include='*' -I . 2>/dev/null | grep -v '^./.git/' | sed 's|^\./||' | sort)

echo "== shellcheck"
if command -v shellcheck >/dev/null; then
    if shellcheck -S warning -x "${sh_files[@]}"; then ok "no warnings"; else bad "shellcheck reported problems"; fi
else
    skip "shellcheck is not installed (apt install shellcheck)"
fi

echo "== Python syntax"
for f in "${py_files[@]}"; do
    # compile() only: nothing is written next to the source
    if out=$(python3 -I -c 'import sys; compile(open(sys.argv[1]).read(), sys.argv[1], "exec")' "$f" 2>&1); then
        ok "$f"
    else
        bad "$f: $out"
    fi
done

echo "== Tetragon policies"
if python3 -I -c 'import yaml' 2>/dev/null; then
    # Parses each policy and checks the limits Tetragon enforces when it loads one: at most 5
    # selectors per hook, and 8 prefix lists and 8 exact-match lists across the whole policy
    if python3 -I - tetragon/policies/*.yaml <<'PY'
import sys, yaml
failed = False
names = set()
for path in sys.argv[1:]:
    try:
        doc = yaml.safe_load(open(path))
        name = doc["metadata"]["name"]
        hooks = doc["spec"]["kprobes"]
    except Exception as e:
        print(f"  FAIL  {path}: {e}"); failed = True; continue
    problems = []
    if name in names:
        problems.append(f"policy name {name!r} is used twice")
    names.add(name)
    prefix = equal = 0
    for hook in hooks:
        selectors = hook.get("selectors", [])
        if len(selectors) > 5:
            problems.append(f'{hook["call"]}: {len(selectors)} selectors (Tetragon allows 5)')
        for sel in selectors:
            for m in sel.get("matchArgs", []):
                prefix += m["operator"] in ("Prefix", "NotPrefix", "Postfix", "NotPostfix")
                equal += m["operator"] in ("Equal", "NotEqual") and any(not str(v).lstrip("-").isdigit() for v in m["values"])
    if prefix > 8:
        problems.append(f"{prefix} prefix/postfix lists (Tetragon allows 8 per policy)")
    if equal > 8:
        problems.append(f"{equal} exact-match string lists (Tetragon allows 8 per policy)")
    for p in problems:
        print(f"  FAIL  {path}: {p}"); failed = True
    if not problems:
        print(f"  ok    {path} ({name}: {len(hooks)} hook(s), {prefix} prefix and {equal} exact-match lists)")
sys.exit(failed)
PY
    then :; else FAIL=1; fi
else
    skip "PyYAML is not installed (apt install python3-yaml)"
fi
if grep -rnE '"/home/[a-z]' tetragon/policies/ >/dev/null; then
    bad "a policy names a home directory; use @HOME@ (filled in at install time)"
    grep -rnE '"/home/[a-z]' tetragon/policies/ | sed 's/^/        /'
else
    ok "no hard-coded home directories (policies use @HOME@)"
fi

echo "== Tetragon export denylist"
if python3 -I - tetragon/export-denylist.jsonl <<'PY'
import json, sys
failed = False
for n, line in enumerate(open(sys.argv[1]), 1):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    try:
        f = json.loads(line)
    except ValueError as e:
        print(f"  FAIL  line {n}: {e}"); failed = True; continue
    # Without one of these the line hides everything a matching process does, policy hits included
    if not f.get("event_set") and not f.get("policy_names"):
        print(f"  FAIL  line {n}: no event_set or policy_names: {line[:80]}"); failed = True
    for key in ("binary_regex", "parent_binary_regex"):
        for rx in f.get(key, []):
            if not rx.startswith("^"):
                print(f"  FAIL  line {n}: {key} {rx!r} is not anchored with ^"); failed = True
if not failed:
    print("  ok    every line is limited to an event type or policy, and binary patterns are anchored")
sys.exit(failed)
PY
then :; else FAIL=1; fi

echo "== Generated Suricata DNS rules"
if out=$(bash controld/files/dns-lockdown-rules.sh 2>&1); then
    sids=$(grep -oE 'sid:[0-9]+' <<<"$out" | sort)
    if [[ -n $(uniq -d <<<"$sids") ]]; then bad "duplicate SIDs: $(uniq -d <<<"$sids" | tr '\n' ' ')"; else ok "$(wc -l <<<"$sids") rules, SIDs unique"; fi
else
    bad "dns-lockdown-rules.sh: $out"
fi

echo "== JSON and notifier patterns"
for f in controld/files/chromium-dns-lockdown.json tetragon/dockerd.json; do
    if python3 -I -c 'import json, sys; json.load(open(sys.argv[1]))' "$f" 2>/dev/null; then ok "$f"; else bad "$f is not valid JSON"; fi
done
if out=$(python3 -I -c '
import re, sys
for n, line in enumerate(open(sys.argv[1]), 1):
    line = line.strip()
    if line and not line.startswith("#"):
        try:
            re.compile(line)
        except re.error as e:
            print(f"line {n}: {e}"); sys.exit(1)
' watch/files/tetragon-ignore.conf 2>&1); then ok "watch/files/tetragon-ignore.conf"; else bad "watch/files/tetragon-ignore.conf: $out"; fi

echo "== systemd units"
if command -v systemd-analyze >/dev/null; then
    # Missing binaries and units are expected on a machine where the kits aren't installed
    out=$(systemd-analyze verify files/*.service files/*.timer controld/files/*.service watch/files/*.service watch/files/*.timer 2>&1 \
        | grep -vE 'is not executable|No such file or directory|not found|Unit .* not found' || true)
    if [[ -z $out ]]; then ok "units parse"; else bad "systemd-analyze verify:"; sed 's/^/        /' <<<"$out"; fi
else
    skip "systemd-analyze is not available"
fi

echo
if [[ $FAIL -eq 0 ]]; then echo "Lint passed"; else echo "Lint FAILED"; fi
exit $FAIL
