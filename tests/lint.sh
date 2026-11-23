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

# One string per list: "printf ... | grep -q" under pipefail reports a false miss when grep quits before printf has finished
sh_list=$(printf '%s\n' "${sh_files[@]}")
py_list=$(printf '%s\n' "${py_files[@]}")

LINT_TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$LINT_TMP"' EXIT

FAIL=0
ok() { echo "  ok    $*"; }
bad() { echo "  FAIL  $*"; FAIL=1; }
skip() { echo "  skip  $*"; }
# A tool that is not installed is a skip on a workstation. When CI is set in the environment it is a failure: a check
# that silently does not run proves nothing. Usage: tool_missing TOOL "message for the skip"
tool_missing() { if [[ -n ${CI:-} ]]; then bad "$1 is not installed, and CI is set: install it (a skipped check is a failed one)"; else skip "$2"; fi; }

echo "== Shell syntax (bash -n)"
n=0
for f in "${sh_files[@]}"; do
    [[ -f $f ]] || { bad "$f is listed in the Makefile but does not exist"; continue; }
    if out=$(bash -n "$f" 2>&1); then n=$((n + 1)); else bad "$f: $out"; fi
done
ok "$n scripts parse"
# Every script in the repo should be on the list, or a new one silently goes unchecked
while IFS= read -r f; do
    grep -qxF -- "$f" <<<"$sh_list" || bad "$f is a shell script but is not in the Makefile's SH_FILES"
done < <(grep -rlE '^#!.*\b(ba)?sh\b' --include='*' -I . 2>/dev/null | grep -v -e '^./.git/' -e '^./dist/' | sed 's|^\./||' | sort)

echo "== shellcheck"
if command -v shellcheck >/dev/null; then
    if shellcheck -S warning -x "${sh_files[@]}"; then ok "no warnings"; else bad "shellcheck reported problems"; fi
else
    tool_missing shellcheck "shellcheck is not installed (apt install shellcheck)"
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
    grep -qxF -- "$f" <<<"$py_list" || bad "$f is a Python script but is not in the Makefile's PY_FILES"
done < <({ git ls-files -co --exclude-standard -- '*.py' 2>/dev/null \
    || find . -name .git -prune -o -name '*.py' -type f -print | sed 's|^\./||'; } | sort -u)
# ... and so should every Python script with no .py name (server_hub/hub/edr-hub, the client helpers): the shebang gives it away
while IFS= read -r f; do
    grep -qxF -- "$f" <<<"$py_list" || bad "$f has a python3 shebang but is not in the Makefile's PY_FILES"
done < <(grep -rlE '^#!.*python3' --include='*' -I . 2>/dev/null | grep -v -e '^./.git/' -e '^./dist/' | sed 's|^\./||' | sort)

echo "== Tetragon policies"
# One run per policy directory: the laptop's, then the server's. A reused laptop policy keeps its metadata.name in
# the server directory; OVERRIDE_NAMES is the explicit list of those, so the cross-directory duplicate check below
# still catches an accidental clash.
OVERRIDE_NAMES="persistence sensitive-files stack-tamper suspicious-exec tcp-listen"
POLICY_DIRS=(tetragon/policies server_edr_solution/server_client/tetragon/policies)
policy_lint() {   # policy_lint [--server] FILE... : the limits Tetragon enforces when it loads a policy
    python3 -I - "$@" <<'PY'
import sys, yaml
args = sys.argv[1:]
server = args and args[0] == "--server"
if server:
    args = args[1:]
failed = False
names = set()
follow_total = 0
for path in args:
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
    calls = set()
    for hook in hooks:
        selectors = hook.get("selectors", [])
        if len(selectors) > 5:
            problems.append(f'{hook["call"]}: {len(selectors)} selectors (Tetragon allows 5)')
        if len(hook.get("args", [])) > 5:
            problems.append(f'{hook["call"]}: {len(hook["args"])} args (Tetragon allows 5)')
        if hook["call"] in calls:
            problems.append(f'{hook["call"]}: two kprobes on one symbol in one policy')
        calls.add(hook["call"])
        for sel in selectors:
            if len(sel.get("matchActions", [])) > 3:
                problems.append(f'{hook["call"]}: {len(sel["matchActions"])} actions in one selector (Tetragon allows 3)')
            for m in sel.get("matchArgs", []):
                prefix += m["operator"] in ("Prefix", "NotPrefix", "Postfix", "NotPostfix")
                equal += m["operator"] in ("Equal", "NotEqual") and any(not str(v).lstrip("-").isdigit() for v in m["values"])
            # matchBinaries Prefix and Postfix lists count towards the same 8
            for m in sel.get("matchBinaries", []):
                prefix += m["operator"] in ("Prefix", "NotPrefix", "Postfix", "NotPostfix")
                if m.get("followChildren"):
                    follow_total += len(m.get("values", []))
    if prefix > 8:
        problems.append(f"{prefix} prefix/postfix lists (Tetragon allows 8 per policy)")
    if equal > 8:
        problems.append(f"{equal} exact-match string lists (Tetragon allows 8 per policy)")
    for p in problems:
        print(f"  FAIL  {path}: {p}"); failed = True
    if not problems:
        print(f"  ok    {path} ({name}: {len(hooks)} hook(s), {prefix} prefix and {equal} exact-match lists)")
if server and follow_total > 64:
    print(f"  FAIL  followChildren paths add up to {follow_total} across the server policies (the budget is 64)"); failed = True
elif server:
    print(f"  ok    followChildren paths across the server policies: {follow_total} of 64")
sys.exit(failed)
PY
}
if python3 -I -c 'import yaml' 2>/dev/null; then
    if policy_lint tetragon/policies/*.yaml; then :; else FAIL=1; fi
    if policy_lint --server server_edr_solution/server_client/tetragon/policies/*.yaml; then :; else FAIL=1; fi
    # The same name in both directories is only allowed for the listed server variants, and the list must not go stale
    if python3 -I - "$OVERRIDE_NAMES" "${POLICY_DIRS[@]}" <<'PY'
import glob, sys, yaml
override = set(sys.argv[1].split())
laptop, server = sys.argv[2], sys.argv[3]
def names(d):
    return {yaml.safe_load(open(p))["metadata"]["name"] for p in glob.glob(d + "/*.yaml")}
same = names(laptop) & names(server)
failed = False
for n in sorted(same - override):
    print(f"  FAIL  policy name {n!r} is in both policy directories and is not on the override list"); failed = True
for n in sorted(override - same):
    print(f"  FAIL  {n!r} is on the override list but is no longer in both directories (remove it from lint.sh)"); failed = True
if not failed:
    print(f"  ok    {len(same)} server variants keep a laptop policy's name (explicit override list); no other name is shared")
sys.exit(failed)
PY
    then :; else FAIL=1; fi
else
    tool_missing PyYAML "PyYAML is not installed (apt install python3-yaml)"
fi
if grep -rnE '"/home/[a-z]' "${POLICY_DIRS[@]}" >/dev/null; then
    bad "a policy names a home directory; use @HOME@ (filled in at install time)"
    grep -rnE '"/home/[a-z]' "${POLICY_DIRS[@]}" | sed 's/^/        /'
else
    ok "no hard-coded home directories (policies use @HOME@)"
fi
# The server policies are rendered from site discovery, never from a home directory: @HOME@ has no value there
if grep -rn '@HOME@' "${POLICY_DIRS[1]}" >/dev/null; then
    bad "a server policy uses @HOME@, which has no value on a server"
    grep -rn '@HOME@' "${POLICY_DIRS[1]}" | sed 's/^/        /'
else
    ok "no @HOME@ in the server policies"
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
    tool_missing PyYAML "PyYAML is not installed (apt install python3-yaml)"
fi

echo "== Tetragon export denylist"
if python3 -I - tetragon/export-denylist.jsonl server_edr_solution/server_client/tetragon/export-denylist.jsonl <<'PY'
import json, os, sys
failed = False
for path in sys.argv[1:]:
    if not os.path.exists(path):
        print(f"  FAIL  {path} does not exist"); failed = True; continue
    for n, line in enumerate(open(path), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            f = json.loads(line)
        except ValueError as e:
            print(f"  FAIL  {path} line {n}: {e}"); failed = True; continue
        # Without one of these the line hides everything a matching process does, policy hits included
        if not f.get("event_set") and not f.get("policy_names"):
            print(f"  FAIL  {path} line {n}: no event_set or policy_names: {line[:80]}"); failed = True
        for key in ("binary_regex", "parent_binary_regex"):
            for rx in f.get(key, []):
                if not rx.startswith("^"):
                    print(f"  FAIL  {path} line {n}: {key} {rx!r} is not anchored with ^"); failed = True
        # Arguments are whatever the process was started with: on their own they hide anything
        # ... so they count only with the root-owned program that started the process, and whole
        if f.get("arguments_regex") and not f.get("parent_binary_regex"):
            print(f"  FAIL  {path} line {n}: arguments_regex without parent_binary_regex: {line[:80]}"); failed = True
        for rx in f.get("arguments_regex", []):
            if not (rx.startswith("^") and rx.endswith("$")):
                print(f"  FAIL  {path} line {n}: arguments_regex {rx[:60]!r} is not anchored at both ends (^...$)"); failed = True
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

echo "== Server JSON and the advisory table"
while IFS= read -r f; do
    if python3 -I -c 'import json, sys; json.load(open(sys.argv[1]))' "$f" 2>/dev/null; then ok "$f"; else bad "$f is not valid JSON"; fi
done < <(find server_edr_solution -name '*.json' -not -path '*/__pycache__/*' -not -path '*/node_modules/*' | sort)
# hub PLAN section 4, Advisory data: the one definition of the file's shape
if out=$(python3 -I - server_edr_solution/common/advisories.json <<'PY' 2>&1
import json, re, sys
doc = json.load(open(sys.argv[1]))
KEYS = ("id", "origin", "release", "packages", "compare", "fixed_in", "cves", "needs_feature", "ref")
errors = []
if not isinstance(doc, dict) or set(doc) != {"updated", "rows"}:
    errors.append('top level must be {"updated", "rows"}')
else:
    if not (isinstance(doc["updated"], str) and re.fullmatch(r"\d{4}-\d\d-\d\d", doc["updated"])):
        errors.append("updated must be YYYY-MM-DD")
    if not isinstance(doc["rows"], list):
        errors.append("rows must be a list")
    seen = set()
    for i, row in enumerate(doc["rows"] if isinstance(doc["rows"], list) else []):
        w = f"row {i}"
        if not isinstance(row, dict):
            errors.append(f"{w}: not an object"); continue
        for k in KEYS:
            if k not in row:
                errors.append(f"{w}: missing key {k}")
        for k in row:
            if k not in KEYS:
                errors.append(f"{w}: unknown key {k}")
        if not (isinstance(row.get("id"), str) and row["id"]):
            errors.append(f"{w}: id must be a non-empty string")
        elif row["id"] in seen:
            errors.append(f"{w}: duplicate id {row['id']}")
        else:
            seen.add(row["id"])
        for k in ("origin", "release", "ref"):
            if k in row and not (isinstance(row[k], str) and row[k]):
                errors.append(f"{w}: {k} must be a non-empty string")
        for k in ("packages", "cves"):
            if k in row and not (isinstance(row[k], list) and all(isinstance(x, str) for x in row[k])):
                errors.append(f"{w}: {k} must be a list of strings")
        if row.get("compare") not in ("dpkg", "upstream", "kernel"):
            errors.append(f"{w}: compare must be dpkg, upstream or kernel")
        for k in ("fixed_in", "needs_feature"):
            if k in row and row[k] is not None and not isinstance(row[k], str):
                errors.append(f"{w}: {k} must be a string or null")
for e in errors:
    print(e)
sys.exit(1 if errors else 0)
PY
); then ok "server_edr_solution/common/advisories.json matches the shape of hub PLAN section 4"; else bad "server_edr_solution/common/advisories.json:"; sed 's/^/        /' <<<"$out"; fi

echo "== Server Python imports (standard library and sibling modules only)"
if out=$(python3 -I - "${py_files[@]}" <<'PY' 2>&1
import ast, os, sys
# The rule covers every Python file under server_edr_solution. A file may import the standard library, modules and
# packages of its own directory (and, inside a package, of the directories above it up to the one that is not a package),
# and relative imports. A test may also import the server code it tests and the other half it round-trips with
# (server_hub/hub and server_client/agent), and PyYAML, which CI requires for the policy checks.
CODE_FOR_TESTS = ("server_hub/hub", "server_client/agent")
TEST_DIRS = ("server_hub/tests", "server_client/tests")
TEST_EXTRA = {"yaml"}
def local_names(d):
    names = set()
    try:
        entries = os.listdir(d)
    except OSError:
        return names
    for e in entries:
        full = os.path.join(d, e)
        if e.endswith(".py"):
            names.add(e[:-3])
        elif os.path.isdir(full) and os.path.exists(os.path.join(full, "__init__.py")):
            names.add(e)
    return names
bad = 0
n = 0
for path in sys.argv[1:]:
    if not path.startswith("server_edr_solution/"):
        continue
    n += 1
    d = os.path.dirname(path)
    allowed = local_names(d)
    up = d
    while os.path.exists(os.path.join(up, "__init__.py")):
        up = os.path.dirname(up)
        allowed |= local_names(up)
    rel = os.path.relpath(d, "server_edr_solution")
    if rel in TEST_DIRS:
        for code in CODE_FOR_TESTS:
            allowed |= local_names(os.path.join("server_edr_solution", code))
        allowed |= TEST_EXTRA
    try:
        tree = ast.parse(open(path).read(), path)
    except SyntaxError as e:
        print(f"  FAIL  {path}: {e}"); bad = 1; continue
    for node in ast.walk(tree):
        mods = []
        if isinstance(node, ast.Import):
            mods = [(a.name.split(".")[0], node.lineno) for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods = [(node.module.split(".")[0], node.lineno)]
        for m, line in mods:
            if m not in sys.stdlib_module_names and m not in allowed:
                print(f"  FAIL  {path}:{line}: imports {m!r}, which is neither the standard library nor a sibling module"); bad = 1
if not bad:
    print(f"  ok    {n} files import only the standard library and their own modules")
sys.exit(bad)
PY
); then ok "${out#  ok    }"; else bad "imports:"; sed 's/^/        /' <<<"$out"; fi

echo "== systemd units"
if command -v systemd-analyze >/dev/null; then
    # Missing binaries and units are expected on a machine where the kits aren't installed
    shopt -s nullglob
    unit_files=(suricata/files/*.service suricata/files/*.timer suricata/files/*.path controld/files/*.service watch/files/*.service watch/files/*.timer
        server_edr_solution/mock/hub/*.service server_edr_solution/mock/web/*.service
        server_edr_solution/server_hub/files/*.{service,timer,path,socket} server_edr_solution/server_client/files/*.{service,timer,path,socket})
    shopt -u nullglob
    out=$(systemd-analyze verify "${unit_files[@]}" 2>&1 \
        | grep -vE 'is not executable|No such file or directory|not found|Unit .* not found' || true)
    if [[ -z $out ]]; then ok "units parse"; else bad "systemd-analyze verify:"; sed 's/^/        /' <<<"$out"; fi

    # Sandbox score of each server service (lower is tighter), in tenths because --threshold takes an integer. The limit is
    # the score measured when this check was added plus 0.2: a loosened unit fails, and a unit without an entry must stay
    # under 3.0.
    declare -A SEC_MAX=(
        [edr-hub]=14 [edr-hub-ui]=13 [edr-hub-out]=14 [edr-hub-failed]=14 [edr-hub-backup]=20 [edr-hub-nft]=96
        [edr-agent]=13 [edr-bans]=22 [edr-diskguard]=25 [edr-dnslock]=22 [edr-dns-watch]=25 [edr-droplet-id]=21
        [edr-home-net]=18 [edr-inventory]=23 [edr-notify]=15 [edr-policy-check]=21 [edr-rules-update]=41)
    sec_n=0
    for u in server_edr_solution/server_hub/files/*.service server_edr_solution/server_client/files/*.service; do
        [[ -f $u ]] || continue
        name=$(basename "$u" .service)
        limit=${SEC_MAX[$name]:-30}
        if out=$(systemd-analyze security --offline=true --threshold="$limit" "$u" 2>&1); then
            sec_n=$((sec_n + 1))
        else
            bad "$u: sandbox exposure is above $((limit / 10)).$((limit % 10)) ($(grep -o 'exposure level for [^:]*: [0-9.]* [A-Z]*' <<<"$out" | sed 's/.*: //'))"
        fi
    done
    ok "$sec_n server services are within their sandbox score limits"
else
    tool_missing systemd-analyze "systemd-analyze is not available"
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
    tool_missing systemd-analyze "systemd-analyze is not available"
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

echo "== Distribution tarballs (make dist)"
# Builds both tarballs in a temp directory (never in dist/), checks the manifests, the agent hash written into the hub tarball,
# that the checked-in agent-hashes.json is untouched and that every file an installer references is in the tarball.
if out=$(tests/dist.sh --check 2>&1); then
    while IFS= read -r line; do ok "$line"; done <<<"$out"
else
    bad "tests/dist.sh --check:"; sed 's/^/        /' <<<"$out"
fi

echo
if [[ $FAIL -eq 0 ]]; then echo "Lint passed"; else echo "Lint FAILED"; fi
exit $FAIL
