#!/bin/bash
# Release tarballs of server_edr_solution (client plan section 7, Delivery; hub plan section 8).
#
#   tests/dist.sh                 build both tarballs into dist/ (normally via: make dist)
#   tests/dist.sh --out DIR       build into DIR instead
#   tests/dist.sh --check         build into a temp directory, verify everything, change nothing (lint.sh runs this)
#
# dist/client/  edr-client-VERSION.tar.gz  .sha256  MANIFEST.sha256  VERSION
# dist/hub/     edr-hub-VERSION.tar.gz     .sha256  MANIFEST.sha256  VERSION
# VERSION and MANIFEST.sha256 are also inside each tarball (MANIFEST.sha256 lists every other file in it). The tarball is
# reproducible: sorted names, owner 0, a fixed time (SOURCE_DATE_EPOCH, default 0) and `gzip -n`, so the same tree gives
# the same hash. The hash to trust is the one printed here, on the build machine; never one that travelled with the tarball.
#
# The hub tarball carries the SHA-256 of the client agent in its agent-hashes.json (the hub's list of accepted builds,
# hub plan section 17). It is written into the staged copy only: the checked-in file is never changed.
set -euo pipefail

ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
cd "$ROOT"
SE=server_edr_solution
OUT=dist
CHECK=0
EPOCH=${SOURCE_DATE_EPOCH:-0}
# Laptop policies the server reuses unchanged; a server directory file of the same name wins (client plan 4.3)
REUSED_POLICIES=(privilege-escalation setuid-files kernel-tampering tetragon-tamper boot-config monitor-kernel-modules)

usage() {
    echo "usage: tests/dist.sh [--out DIR | --check]   (build both tarballs into dist/, or verify a build in a temp directory)"
    exit "${1:-64}"
}
while [[ $# -gt 0 ]]; do
    case $1 in
        --check) CHECK=1 ;;
        --out) [[ $# -ge 2 ]] || usage; OUT=$2; shift ;;
        -h|--help) usage 0 ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
    shift
done
for tool in tar gzip sha256sum python3 find; do
    command -v "$tool" >/dev/null || { echo "dist.sh needs $tool" >&2; exit 2; }
done

WORK=$(mktemp -d) || exit 2
trap 'rm -rf "$WORK"' EXIT
[[ $CHECK -eq 0 ]] || OUT=$WORK/dist

version_of() { sed -n 's/^VERSION *= *"\([^"]*\)".*/\1/p' "$1" | head -1; }
CLIENT_VERSION=$(version_of "$SE/server_client/agent/edragent/__init__.py")
HUB_VERSION=$(version_of "$SE/server_hub/hub/hub_common.py")
[[ -n $CLIENT_VERSION && -n $HUB_VERSION ]] || { echo "dist.sh: cannot read the version numbers" >&2; exit 2; }

clean_tree() {   # no bytecode, no editor leftovers
    find "$1" \( -name __pycache__ -o -name '*.pyc' -o -name '*~' -o -name '*.swp' \) -prune -exec rm -rf {} +
}

# ---- Staging ---------------------------------------------------------------------------------------------
stage_client() {   # stage_client DIR
    local d=$1 src=$SE/server_client f p
    mkdir -p "$d"
    cp -a "$src/agent" "$src/files" "$d/"
    mkdir -p "$d/tetragon/policies"
    cp -a "$src/tetragon/." "$d/tetragon/"
    for f in install.sh uninstall.sh check.sh PLAN.md; do      # PLAN.md: units name it in Documentation=
        [[ ! -f $src/$f ]] || cp -a "$src/$f" "$d/$f"
    done
    # reused laptop files: the policies that need no change, and the DNS rule generator
    for p in "${REUSED_POLICIES[@]}"; do
        [[ -e $d/tetragon/policies/$p.yaml ]] || cp -a "tetragon/policies/$p.yaml" "$d/tetragon/policies/$p.yaml"
    done
    cp -a controld/files/dns-lockdown-rules.sh "$d/files/dns-lockdown-rules.sh"
    cp -a tetragon/config.sh "$d/tetragon/config.sh"      # the Tetragon version pin, read by the server check.sh and installer
    # the advisory table: edr-inventory judges package fixes from it (the installer copies it beside the code)
    mkdir -p "$d/common"
    cp -a "$SE/common/advisories.json" "$d/common/advisories.json"
    clean_tree "$d"
    printf '%s\n' "$CLIENT_VERSION" > "$d/VERSION"
}

agent_sha256() {   # agent_sha256 TREE : as the agent reports it (edr-agent.py version --hash)
    python3 -I -B "$1/agent/edr-agent.py" version --hash | sed -n '2p'
}

stage_hub() {   # stage_hub DIR AGENT_SHA256
    local d=$1 sha=$2 src=$SE/server_hub f
    mkdir -p "$d/common"
    cp -a "$src/hub" "$src/files" "$src/pki" "$src/docs" "$d/"
    for f in install.sh uninstall.sh check.sh PLAN.md; do
        [[ ! -f $src/$f ]] || cp -a "$src/$f" "$d/$f"
    done
    cp -a "$SE/common/advisories.json" "$d/common/advisories.json"
    clean_tree "$d"
    # the hub's accepted agent builds: the one in this release (the checked-in file stays as it is)
    printf '{"hashes": ["%s"]}\n' "$sha" > "$d/hub/agent-hashes.json"
    printf '%s\n' "$HUB_VERSION" > "$d/VERSION"
}

pack() {   # pack STAGEDIR NAME OUTDIR : MANIFEST.sha256, the tarball, its .sha256, and copies of VERSION and the manifest
    local stage=$1 name=$2 out=$3 tree
    tree=$stage/$name
    (cd "$tree" && find . -type f ! -name MANIFEST.sha256 -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum) > "$stage/MANIFEST.sha256"
    mv "$stage/MANIFEST.sha256" "$tree/MANIFEST.sha256"
    mkdir -p "$out"
    tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH" -cf - -C "$stage" "$name" | gzip -n -9 > "$out/$name.tar.gz"
    (cd "$out" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
    cp "$tree/VERSION" "$tree/MANIFEST.sha256" "$out/"
}

build() {   # build OUTDIR : both tarballs
    local out=$1 stage sha
    stage=$(mktemp -d "$WORK/stage.XXXXXX")
    rm -rf "${out:?}/client" "${out:?}/hub"
    stage_client "$stage/edr-client-$CLIENT_VERSION"
    sha=$(agent_sha256 "$stage/edr-client-$CLIENT_VERSION")
    [[ $sha =~ ^[0-9a-f]{64}$ ]] || { echo "dist.sh: the agent did not report a SHA-256" >&2; exit 2; }
    stage_hub "$stage/edr-hub-$HUB_VERSION" "$sha"
    mkdir -p "$stage/c" "$stage/h"
    mv "$stage/edr-client-$CLIENT_VERSION" "$stage/c/"
    mv "$stage/edr-hub-$HUB_VERSION" "$stage/h/"
    pack "$stage/c" "edr-client-$CLIENT_VERSION" "$out/client"
    pack "$stage/h" "edr-hub-$HUB_VERSION" "$out/hub"
    AGENT_SHA=$sha
}

if [[ $CHECK -eq 0 ]]; then
    build "$OUT"
    echo "Built in $OUT/:"
    for t in "$OUT/client/edr-client-$CLIENT_VERSION.tar.gz" "$OUT/hub/edr-hub-$HUB_VERSION.tar.gz"; do
        printf '  %s  %s files  %s\n' "$(sha256sum "$t" | cut -c1-64)" "$(tar -tzf "$t" | grep -vc '/$')" "$t"
    done
    echo "Agent SHA-256 (in the hub tarball's agent-hashes.json): $AGENT_SHA"
    echo "Compare the tarball hashes above with the .sha256 files on the machine you copy them to; never trust a hash that travelled with the tarball."
    exit 0
fi

# ---- --check ---------------------------------------------------------------------------------------------
FAILED=0
good() { echo "$*"; }
broken() { echo "FAIL: $*"; FAILED=1; }

checked_in_before=$(sha256sum "$SE/server_hub/hub/agent-hashes.json" | cut -c1-64)
build "$OUT"
first_client=$(cut -c1-64 "$OUT/client/edr-client-$CLIENT_VERSION.tar.gz.sha256")
first_hub=$(cut -c1-64 "$OUT/hub/edr-hub-$HUB_VERSION.tar.gz.sha256")
build "$OUT"
if [[ $first_client == "$(cut -c1-64 "$OUT/client/edr-client-$CLIENT_VERSION.tar.gz.sha256")" \
   && $first_hub == "$(cut -c1-64 "$OUT/hub/edr-hub-$HUB_VERSION.tar.gz.sha256")" ]]; then
    good "dist: two builds give the same tarball hashes"
else
    broken "two builds of the same tree give different tarballs (something in them is not reproducible)"
fi
if [[ $checked_in_before == "$(sha256sum "$SE/server_hub/hub/agent-hashes.json" | cut -c1-64)" ]]; then
    good "dist: the checked-in server_hub/hub/agent-hashes.json was not touched"
else
    broken "the build changed the checked-in server_hub/hub/agent-hashes.json"
fi

X=$WORK/x
mkdir -p "$X/client" "$X/hub"
for kind in client hub; do
    ver=$CLIENT_VERSION; [[ $kind == hub ]] && ver=$HUB_VERSION
    name=edr-$kind-$ver
    tb=$OUT/$kind/$name.tar.gz
    if (cd "$OUT/$kind" && sha256sum -c --quiet "$name.tar.gz.sha256" >/dev/null 2>&1); then good "dist: $kind tarball matches its .sha256"; else broken "$kind tarball does not match its .sha256"; fi
    tar -xzf "$tb" -C "$X/$kind"
    tree=$X/$kind/$name
    if (cd "$tree" && sha256sum -c --quiet MANIFEST.sha256 >/dev/null 2>&1); then good "dist: $kind MANIFEST.sha256 verifies every file"; else broken "$kind MANIFEST.sha256 does not verify"; fi
    listed=$(cut -c67- "$tree/MANIFEST.sha256" | LC_ALL=C sort)
    present=$(cd "$tree" && find . -type f ! -name MANIFEST.sha256 -printf '%P\n' | LC_ALL=C sort)
    [[ $listed == "$present" ]] && good "dist: $kind manifest lists exactly the files in the tarball ($(wc -l <<<"$present") files)" || broken "$kind manifest and tarball hold different files"
    [[ $(cat "$tree/VERSION") == "$ver" && $(cat "$OUT/$kind/VERSION") == "$ver" ]] && good "dist: $kind VERSION is $ver" || broken "$kind VERSION is wrong"
    cmp -s "$tree/MANIFEST.sha256" "$OUT/$kind/MANIFEST.sha256" || broken "$kind MANIFEST.sha256 beside the tarball differs from the one inside"
    stray=$(cd "$tree" && find . \( -name __pycache__ -o -name '*.pyc' -o -name tests -o -name .git \) | head -5)
    [[ -z $stray ]] || broken "$kind tarball holds files a server does not need: $(tr '\n' ' ' <<<"$stray")"
done

# the agent hash in the hub tarball is the hash of the agent in the client tarball
fresh=$(agent_sha256 "$X/client/edr-client-$CLIENT_VERSION")
inhub=$(python3 -I -c 'import json, sys; print(" ".join(json.load(open(sys.argv[1]))["hashes"]))' "$X/hub/edr-hub-$HUB_VERSION/hub/agent-hashes.json")
if [[ $fresh == "$inhub" ]]; then good "dist: the hub's agent-hashes.json holds the client agent's SHA-256 (${fresh:0:16}...)"; else broken "agent-hashes.json in the hub tarball ($inhub) is not the agent's SHA-256 ($fresh)"; fi
live=$(python3 -I -B "$SE/server_client/agent/edr-agent.py" version --hash | sed -n '2p')
[[ $live == "$fresh" ]] || broken "the agent in the tarball hashes differently from the one in the checkout"

# every program the units name is in the hub tarball, and every file an installer or check script refers to is in its tarball
python3 -I - "$X/hub/edr-hub-$HUB_VERSION" "$X/client/edr-client-$CLIENT_VERSION" "$SE" <<'PY' || FAILED=1
import os, re, sys
hub_tree, client_tree, se = sys.argv[1:4]
bad = 0

def exists_anywhere(tree, name):
    for root, _dirs, files in os.walk(tree):
        if name in files or name in _dirs:
            return True
    return False

# 1. units: the paths under /usr/local/lib/edr-hub and /usr/local/lib/edr-agent they run
checked = 0
for tree, unit_dir, prefix in ((hub_tree, "files", "/usr/local/lib/edr-hub/"), (client_tree, "files", "/usr/local/lib/edr-agent/")):
    d = os.path.join(tree, unit_dir)
    for fn in sorted(os.listdir(d)):
        if not fn.endswith((".service", ".timer", ".path", ".socket")):
            continue
        text = open(os.path.join(d, fn), errors="replace").read()
        for m in re.finditer(re.escape(prefix) + r"([A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+-]+)*)", text):
            checked += 1
            if not exists_anywhere(tree, os.path.basename(m.group(1))):
                print(f"FAIL: {fn} runs {prefix}{m.group(1)}, which is not in the tarball"); bad = 1
if not bad:
    print(f"dist: {checked} program paths named by the units are in their tarballs")

# 2. installers: files/NAME, agent/NAME, tetragon/NAME ... written relative to the unpacked tree
REF = re.compile(r"(?:\$\{?(?:SRC|HERE|ROOT|DIR|SCRIPT_DIR|SELF|SRCDIR|KIT|TREE)\}?|\.)/((?:files|agent|tetragon|pki|common|hub|docs)/[\w@.+-]+(?:/[\w@.+-]+)*)")
for kind, tree in (("server_client", client_tree), ("server_hub", hub_tree)):
    for script in ("install.sh", "uninstall.sh", "check.sh"):
        path = os.path.join(se, kind, script)
        if not os.path.exists(path):
            print(f"dist: {kind}/{script} is not written yet: its file references are not checked")
            continue
        n = missing = 0
        for m in REF.finditer(open(path, errors="replace").read()):
            n += 1
            if not os.path.exists(os.path.join(tree, m.group(1))):
                print(f"FAIL: {kind}/{script} refers to {m.group(1)}, which is not in the tarball"); bad = missing = 1
        if not missing:
            print(f"dist: {kind}/{script}: {n} file references, all in the tarball")
sys.exit(bad)
PY

exit $FAILED
