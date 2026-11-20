#!/bin/bash
# Static checks for the scripts, Python, policies, generated rules, JSON and units in the repo. Changes nothing and needs nothing installed
# beyond bash and python3; the optional tools are used when present and reported as skipped
# when not (shellcheck, PyYAML, systemd-analyze, logrotate). Its only writes go to a temp
# directory of its own, removed at the end.
#
# Usage: tests/lint.sh SHELL-FILES... -- PYTHON-FILES...     (normally via: make lint)
set -uo pipefail

ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
cd "$ROOT" || exit 1

sh_files=() py_files=() in_py=0
for arg in "$@"; do
    if [[ $arg == -- ]]; then in_py=1; elif [[ $in_py -eq 1 ]]; then py_files+=("$arg"); else sh_files+=("$arg"); fi
done

LINT_TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$LINT_TMP"' EXIT

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
# The Python that ips-watch carries inside itself: a syntax error there would silently switch
# off the reporting of Suricata's findings
sed -n "/python3 -I -c '\$/,/^'\$/p" watch/files/ips-watch | sed '1d;$d' > "$LINT_TMP/ips-watch.py"
if [[ ! -s $LINT_TMP/ips-watch.py ]]; then
    bad "watch/files/ips-watch: its embedded Python was not found (lint.sh looks for python3 -I -c ' ... ')"
elif out=$(python3 -I -c 'import sys; compile(open(sys.argv[1]).read(), "ips-watch (embedded Python)", "exec")' "$LINT_TMP/ips-watch.py" 2>&1); then
    ok "watch/files/ips-watch (embedded Python)"
else
    bad "watch/files/ips-watch (embedded Python): $out"
fi
# Every Python file in the repo should be on the list, or a new one silently goes uncompiled
while IFS= read -r f; do
    printf '%s\n' "${py_files[@]}" | grep -qxF -- "$f" || bad "$f is a Python script but is not in the Makefile's PY_FILES"
done < <({ git ls-files -co --exclude-standard -- '*.py' 2>/dev/null \
    || find . -name .git -prune -o -name '*.py' -type f -print | sed 's|^\./||'; } | sort -u)

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

echo "== Suricata config"
if python3 -I -c 'import yaml' 2>/dev/null; then
    # The template only parses once the interface placeholder is filled in
    if out=$(sed 's/@DEFAULT_IFACE@/eth0/' suricata/files/suricata.yaml | python3 -I -c '
import sys, yaml
d = yaml.safe_load(sys.stdin)
assert d["nfq"]["fail-open"] is False, "nfq.fail-open must be no"
assert d["stream"]["midstream"] is True, "stream.midstream must be yes"
assert d["security"]["landlock"]["enabled"] is True, "security.landlock.enabled must be yes"
' 2>&1); then ok "suricata/files/suricata.yaml parses; fail-closed queue, midstream and landlock are set"; else bad "suricata/files/suricata.yaml: $out"; fi
    if out=$(python3 -I -c '
import re, sys
for n, line in enumerate(open(sys.argv[1]), 1):
    if line.startswith("re:"):
        try:
            re.compile(line[3:].strip())
        except re.error as e:
            print(f"line {n}: {e}"); sys.exit(1)
' suricata/files/drop.conf 2>&1); then ok "suricata/files/drop.conf: every re: line compiles"; else bad "suricata/files/drop.conf: $out"; fi
else
    skip "PyYAML is not installed (apt install python3-yaml)"
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
    # Arguments are whatever the process was started with: on their own they hide anything
    # ... so they count only with the root-owned program that started the process, and whole
    if f.get("arguments_regex") and not f.get("parent_binary_regex"):
        print(f"  FAIL  line {n}: arguments_regex without parent_binary_regex: {line[:80]}"); failed = True
    for rx in f.get("arguments_regex", []):
        if not (rx.startswith("^") and rx.endswith("$")):
            print(f"  FAIL  line {n}: arguments_regex {rx[:60]!r} is not anchored at both ends (^...$)"); failed = True
if not failed:
    print("  ok    every line is limited to an event type or policy, binary patterns are anchored, and arguments match whole and only under a named parent")
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
    out=$(systemd-analyze verify suricata/files/*.service suricata/files/*.timer controld/files/*.service watch/files/*.service watch/files/*.timer \
        server_edr_solution/mock/hub/*.service server_edr_solution/mock/web/*.service 2>&1 \
        | grep -vE 'is not executable|No such file or directory|not found|Unit .* not found' || true)
    if [[ -z $out ]]; then ok "units parse"; else bad "systemd-analyze verify:"; sed 's/^/        /' <<<"$out"; fi
else
    skip "systemd-analyze is not available"
fi

echo "== Drop-ins and the units the Tetragon installer writes"
NOISE='is not executable|No such file or directory|not found|Unit .* not found'
if command -v systemd-analyze >/dev/null; then
    # A drop-in is only read as part of a unit: give ctrld's two a stand-in unit to belong to
    mkdir -p "$LINT_TMP/ctrld/ctrld.service.d"
    printf '[Service]\nExecStart=/bin/true\n' > "$LINT_TMP/ctrld/ctrld.service"
    cp controld/files/ctrld-50-dns-lockdown.conf controld/files/ctrld-60-hardening.conf "$LINT_TMP/ctrld/ctrld.service.d/"
    out=$(systemd-analyze verify "$LINT_TMP/ctrld/ctrld.service" 2>&1 | grep -vE "$NOISE" || true)
    if [[ -z $out ]]; then ok "ctrld drop-ins parse"; else bad "ctrld drop-ins:"; sed 's/^/        /' <<<"$out"; fi

    # tetragon/local_install.sh writes its units from here-documents. Replay just those (and
    # the plain assignments they use) into the temp directory, then check what comes out.
    if python3 -I - tetragon/local_install.sh > "$LINT_TMP/gen.sh" <<'PY'
import re, sys
lines = open(sys.argv[1]).read().split("\n")
assign, docs, i = [], [], 0
while i < len(lines):
    line = lines[i]
    m = re.match("\\s*cat >(\"[^\"]+\") <<('?)EOF'?$", line)
    if m:
        end = lines.index("EOF", i + 1)
        body = lines[i + 1:end]
        # Unquoted, the shell expands the text: nothing in it may run a command
        if not m.group(2) and any("$(" in b or "`" in b for b in body):
            sys.stderr.write(f"line {i + 1}: a here-document with a command substitution cannot be checked\n")
            sys.exit(1)
        docs.append((m.group(1), m.group(2), body))
        i = end + 1
        continue
    if re.match("[A-Za-z_][A-Za-z0-9_]*\\+?=", line) and "$(" not in line and "`" not in line:
        assign.append(line)
    i += 1
if len(docs) < 5:
    sys.stderr.write(f"found {len(docs)} generated files in {sys.argv[1]}, expected at least 5: lint.sh needs updating\n")
    sys.exit(1)
print("DIR=/opt/kit/tetragon")
print("\n".join(assign))
print("set -u    # a misspelt variable in a unit must not expand to nothing")
for target, quote, body in docs:
    print(f'cat > "$OUT/$(basename {target})" <<{quote}EOF{quote}')
    print("\n".join(body))
    print("EOF")
PY
    then
        mkdir -p "$LINT_TMP/tetragon/tetragon.service.d"
        # shellcheck disable=SC2016   # expanded by the inner shell, on purpose
        if out=$(OUT="$LINT_TMP/tetragon" bash -c '. tetragon/config.sh; . "$1"' _ "$LINT_TMP/gen.sh" 2>&1); then
            printf '[Service]\nExecStart=/bin/true\n' > "$LINT_TMP/tetragon/tetragon.service"
            mv "$LINT_TMP/tetragon/boot-gate.conf" "$LINT_TMP/tetragon/shutdown.conf" "$LINT_TMP/tetragon/tetragon.service.d/" 2>/dev/null \
                || bad "tetragon/local_install.sh no longer writes boot-gate.conf and shutdown.conf (lint.sh needs updating)"
            out=$(systemd-analyze verify "$LINT_TMP"/tetragon/*.service 2>&1 | grep -vE "$NOISE" || true)
            if [[ -z $out ]]; then
                ok "tetragon units and drop-ins parse (written by local_install.sh: $(cd "$LINT_TMP/tetragon" && find . -name '*.service' -o -name '*.conf' | grep -vc '^\./tetragon\.service$') files)"
            else
                bad "units written by tetragon/local_install.sh:"; sed 's/^/        /' <<<"$out"
            fi
            if out=$(sh -n "$LINT_TMP/tetragon/tetragon-wait-ready" 2>&1); then ok "tetragon-wait-ready parses"; else bad "tetragon-wait-ready: $out"; fi
        else
            bad "the units in tetragon/local_install.sh could not be generated: $out"
        fi
    else
        bad "tetragon/local_install.sh: its here-documents could not be read (see the message above)"
    fi
else
    skip "systemd-analyze is not available"
fi

echo "== tmpfiles and logrotate"
if systemd-tmpfiles --help 2>/dev/null | grep -q -- '--dry-run'; then
    out=$(systemd-tmpfiles --create --dry-run controld/files/ctrld-logs.tmpfiles 2>&1 | grep -E '^[^ ]*ctrld-logs\.tmpfiles:[0-9]+:' || true)
    if [[ -z $out ]]; then ok "controld/files/ctrld-logs.tmpfiles"; else bad "controld/files/ctrld-logs.tmpfiles:"; sed 's/^/        /' <<<"$out"; fi
else
    skip "systemd-tmpfiles has no --dry-run here"
fi
if command -v logrotate >/dev/null; then
    for f in suricata/files/suricata.logrotate controld/files/ctrld.logrotate; do
        # A copy: logrotate refuses a file that belongs to someone else. -d changes nothing.
        cp "$f" "$LINT_TMP/logrotate.conf"
        out=$(logrotate -d -s "$LINT_TMP/logrotate.state" "$LINT_TMP/logrotate.conf" 2>&1 | grep -E 'unknown option|error: .*logrotate\.conf' || true)
        if [[ -z $out ]]; then ok "$f"; else bad "$f:"; sed 's/^/        /' <<<"$out"; fi
    done
else
    skip "logrotate is not installed"
fi

echo
if [[ $FAIL -eq 0 ]]; then echo "Lint passed"; else echo "Lint FAILED"; fi
exit $FAIL
