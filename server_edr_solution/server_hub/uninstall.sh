#!/bin/bash
# Remove what server_hub/install.sh set up (PLAN.md section 9). Data and users stay unless --purge.
#
#   sudo ./uninstall.sh            asks first; keeps the database, the CA, the backups and the users
#   sudo ./uninstall.sh --yes      does not ask the first question
#   sudo ./uninstall.sh --purge    also deletes the data, the backups and the four users (two more questions)
#   ./uninstall.sh --plan          prints every step it would take and exits 0; changes nothing, needs no root
#
# Exit codes (PLAN section 17): 0 done and the final check passed, 2 the final check failed,
# 3 nothing to remove or a prompt was declined or the manifest was refused, 64 usage error.
#
# What it never does: flush or touch any nftables table but `inet edr_hub`, remove a package, or delete a
# file the manifest does not list (those are printed). The manifest, /etc/edr-hub/manifest.jsonl, is parsed
# by python3 -I and every field in it is treated as untrusted.
set -uo pipefail

STATE=${EDR_HUB_STATE_DIR:-/var/lib/edr-hub}
RUN=${EDR_HUB_RUN_DIR:-/run/edr-hub}
ETC=${EDR_HUB_ETC_DIR:-/etc/edr-hub}
BACKUPS=${EDR_HUB_BACKUP_DIR:-/var/backups/edr-hub}
OUTSTATE=${EDR_HUB_OUT_STATE_DIR:-/var/lib/edr-hub-out}
CASTATE=/var/lib/edr-hub-ca
MANIFEST=$ETC/manifest.jsonl
CLI=/usr/local/sbin/edr-hub
CODE_DIRS="/usr/local/lib/edr-hub /usr/local/lib/edr-hub.prev"
HUB_IDS="edr-hub edr-hub-ui edr-hub-out edr-hub-ca"
JOURNAL_CONF=/etc/systemd/journald@edr-hub.conf
KEEPERS="secrets.json backup.pass"

ASSUME_YES=0 PURGE=0 PLAN=0

usage() {
    cat >&2 <<'EOF'
usage: uninstall.sh [--yes] [--purge] [--plan]
  --yes     do not ask the first question (--purge still asks twice unless --yes is given too)
  --purge   also delete /var/lib/edr-hub, /var/lib/edr-hub-out, /var/lib/edr-hub-ca, /etc/edr-hub,
            /var/backups/edr-hub and the four edr-hub users and groups
  --plan    print every step and exit 0 without changing anything
EOF
}

for arg in "$@"; do
    case $arg in
        --yes|-y) ASSUME_YES=1 ;;
        --purge) PURGE=1 ;;
        --plan) PLAN=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; usage; exit 64 ;;
    esac
done

say() { printf '\n==> %s\n' "$*"; }

# ---- read-only helpers (the plan uses these too) --------------------------------------------------------

# A directory this script may delete: absolute, no .., no spaces, and not a system directory.
guard_dir() {
    case $1 in
        /|/etc|/var|/usr|/home|/root|/run|/tmp|/opt|/boot|/bin|/sbin|/lib|/var/lib|/var/backups|/usr/local|\
/usr/local/lib|/usr/local/sbin|/etc/systemd|/etc/systemd/system) return 1 ;;
        /*) ;;
        *) return 1 ;;
    esac
    case $1 in
        *..*|*[[:space:]]*|*//*) return 1 ;;
    esac
    return 0
}

for d in "$STATE" "$RUN" "$ETC" "$BACKUPS" "$OUTSTATE"; do
    guard_dir "$d" || { echo "Refusing to work on the directory '$d'" >&2; exit 3; }
done

# The ports the hub listened on, read before anything is deleted (for the final check).
read_ports() {
    local out
    out=$(python3 -I - "$STATE/settings.json" <<'PY' 2>/dev/null
import json, sys
ports = {"port": 8443, "enroll_port": 8444, "ui_port": 8450}
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
    for key in ports:
        value = data.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and 0 < value < 65536:
            ports[key] = value
except (OSError, ValueError, AttributeError):
    pass
print(ports["port"], ports["enroll_port"], ports["ui_port"])
PY
    )
    if [[ $out =~ ^[0-9]+\ [0-9]+\ [0-9]+$ ]]; then echo "$out"; else echo "8443 8444 8450"; fi
}

# Parse the manifest (read-only). Prints one tab-separated line per thing, last installed first:
#   manifest <state>                     state: ok | missing | unreadable
#   refuse <line> <reason>               a line that is not acceptable; a real run stops before changing anything
#   entry <kind> <path> <prior> <saved> <state>
#       prior: absent | present | saved   state: ok | missing | edited | notfile | unknown | -
# For one path the FIRST line's prior is what to go back to and the LAST line's sha256 is what the kit wrote.
parse_manifest() {
    python3 -I - "$MANIFEST" "$ETC" <<'PY'
import hashlib, json, os, re, sys

manifest, etc = sys.argv[1], os.path.normpath(sys.argv[2])
MAX_TOTAL, MAX_LINE = 4 * 1024 * 1024, 4096
PATH_RE = re.compile(r"^/[A-Za-z0-9._@+:/-]+$")
NAME_RE = re.compile(r"^[A-Za-z0-9._@+:-]{1,64}$")
KINDS = ("file", "dir", "unit", "user", "group", "package", "link")
IDS = ("edr-hub", "edr-hub-ui", "edr-hub-out", "edr-hub-ca")
EXACT = ("/etc/systemd/journald@edr-hub.conf", "/etc/apt/apt.conf.d/52edr-hub", "/usr/local/sbin/edr-hub")
TREES = (etc, "/usr/local/lib/edr-hub", "/usr/local/lib/edr-hub.prev")


def clean(text):
    return "".join(c if " " <= c <= "~" and c != "\t" else "?" for c in str(text))[:60]


def owned(path):
    if not isinstance(path, str) or len(path) > 400 or not PATH_RE.match(path) or path.endswith("/"):
        return False
    parts = path.split("/")[1:]
    if "" in parts or "." in parts or ".." in parts:
        return False
    if path in EXACT:
        return True
    if any(path == t or path.startswith(t + "/") for t in TREES):
        return True
    return len(parts) >= 4 and parts[:3] == ["etc", "systemd", "system"] and parts[3].startswith("edr-hub")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


try:
    size = os.path.getsize(manifest)
except FileNotFoundError:
    print("manifest\tmissing")
    sys.exit(0)
except OSError:
    print("manifest\tunreadable")
    sys.exit(0)
if size > MAX_TOTAL:
    print("manifest\tunreadable")
    print("refuse\t0\tmanifest is larger than 4 MiB")
    sys.exit(0)
print("manifest\tok")

order, first_prior, last_sha = [], {}, {}
with open(manifest, encoding="utf-8", errors="replace") as f:
    for number, raw in enumerate(f, 1):
        if not raw.strip():
            continue
        if len(raw) > MAX_LINE:
            print("refuse\t%d\tline is too long" % number)
            continue
        try:
            item = json.loads(raw)
            kind, path, prior = item["kind"], item["path"], item["prior"]
        except (ValueError, KeyError, TypeError):
            print("refuse\t%d\tnot a manifest line" % number)
            continue
        if kind not in KINDS:
            print("refuse\t%d\tunknown kind %s" % (number, clean(kind)))
            continue
        if kind in ("file", "dir", "link"):
            if not owned(path):
                print("refuse\t%d\tpath outside the directories the kit owns: %s" % (number, clean(path)))
                continue
        elif not isinstance(path, str) or not NAME_RE.match(path) or \
                (kind == "unit" and not path.startswith("edr-hub")) or (kind in ("user", "group") and path not in IDS):
            print("refuse\t%d\tbad %s name: %s" % (number, kind, clean(path)))
            continue
        saved = ""
        if prior in ("absent", "present"):
            state = prior
        elif isinstance(prior, dict) and set(prior) == {"saved"} and isinstance(prior["saved"], str) \
                and owned(prior["saved"]) and prior["saved"].startswith(etc + "/prior/"):
            state, saved = "saved", prior["saved"]
        else:
            print("refuse\t%d\tbad prior for %s" % (number, clean(path)))
            continue
        key = (kind, path)
        if key not in first_prior:
            first_prior[key] = (state, saved)
            order.append(key)
        sha = item.get("sha256")
        if isinstance(sha, str) and re.match(r"^[0-9a-f]{64}$", sha):
            last_sha[key] = sha

for key in reversed(order):
    kind, path = key
    state, saved = first_prior[key]
    cond = "-"
    if kind == "file":
        if not os.path.lexists(path):
            cond = "missing"
        elif os.path.islink(path) or not os.path.isfile(path):
            cond = "notfile"
        elif key in last_sha:
            try:
                cond = "ok" if sha256(path) == last_sha[key] else "edited"
            except OSError:
                cond = "unknown"
        else:
            cond = "unknown"
    elif kind == "link":
        cond = "ok" if os.path.islink(path) else "missing" if not os.path.lexists(path) else "notfile"
    elif kind == "dir":
        cond = "ok" if os.path.isdir(path) and not os.path.islink(path) else "missing"
    print("entry\t%s\t%s\t%s\t%s\t%s" % (kind, path, state, saved or "-", cond))
PY
}

# What to do with one manifest entry. Pure: the plan prints it, the run does it.
classify() {   # kind path prior state
    local kind=$1 path=$2 prior=$3 cond=$4
    case $kind in
        file|link)
            case $cond in
                notfile) echo LEAVE_NOTFILE ;;
                missing) [[ $prior == saved ]] && echo RESTORE || echo GONE ;;
                edited)
                    case $prior in
                        absent) echo REMOVE_EDITED ;;
                        saved) echo LEAVE_EDITED ;;
                        *) echo LEAVE_PRESENT ;;
                    esac ;;
                *)
                    case $prior in
                        absent) echo REMOVE ;;
                        saved) echo RESTORE ;;
                        *) echo LEAVE_PRESENT ;;
                    esac ;;
            esac ;;
        dir)
            if [[ $cond == missing ]]; then echo GONE
            elif [[ $prior != absent ]]; then echo LEAVE_PRESENT
            elif [[ $path == /usr/local/lib/edr-hub || $path == /usr/local/lib/edr-hub.prev ]]; then echo REMOVE_TREE
            elif [[ $path == "$ETC" ]]; then echo ETC_LATER
            else echo RMDIR
            fi ;;
        unit) [[ $prior == absent ]] && echo UNIT_OFF || echo LEAVE_PRESENT ;;
        user|group) [[ $prior == present ]] && echo LEAVE_PRESENT || echo KEEP_ID ;;
        package) echo PACKAGE ;;
        *) echo LEAVE_PRESENT ;;
    esac
}

describe() {   # action kind path
    case $1 in
        REMOVE) echo "remove $3" ;;
        REMOVE_EDITED) echo "remove $3 (changed since install; the manifest says it did not exist before)" ;;
        RESTORE) echo "put the saved prior copy back at $3" ;;
        RMDIR) echo "remove directory $3 if it is empty" ;;
        REMOVE_TREE) echo "remove $3 and everything under it (the kit's code)" ;;
        UNIT_OFF) echo "stop and disable unit $3, forget its failed state" ;;
        KEEP_ID) echo "keep $2 $3 (--purge deletes it)" ;;
        PACKAGE) echo "leave package $3 installed (no package is ever removed)" ;;
        GONE) echo "$3 is already gone" ;;
        LEAVE_EDITED) echo "leave $3: changed since install and a prior copy exists; check it by hand" ;;
        LEAVE_NOTFILE) echo "leave $3: it is not the file the kit wrote" ;;
        LEAVE_PRESENT) echo "leave $3: it existed before the kit" ;;
        ETC_LATER) echo "$3 is handled at the end of step 4" ;;
        *) echo "$1 $3" ;;
    esac
}

# Everything the kit may have left, to print what the manifest did not take care of.
leftover_paths() {
    local p
    for p in /etc/systemd/system/edr-hub* "$JOURNAL_CONF" /etc/apt/apt.conf.d/52edr-hub $CODE_DIRS "$CLI"; do
        [[ -e $p || -L $p ]] && echo "$p"
    done
}

etc_extras() {   # items in /etc/edr-hub that are neither kept nor the kit's own bookkeeping
    local p base
    for p in "$ETC"/* "$ETC"/.[!.]*; do
        [[ -e $p || -L $p ]] || continue
        base=${p##*/}
        case " $KEEPERS manifest.jsonl prior " in *" $base "*) continue ;; esac
        echo "$p"
    done
}

nothing_installed() {
    local p
    for p in "$ETC" "$STATE" "$CLI" $CODE_DIRS /etc/systemd/system/edr-hub*; do
        [[ -e $p || -L $p ]] && return 1
    done
    return 0
}

# ---- --plan: print the steps and stop; nothing below this function can run before it exits ---------------
plan() {
    local ports tag f1 f2 f3 f5 action refused=0
    echo "uninstall.sh --plan: nothing is changed."
    echo "State $STATE, etc $ETC, backups $BACKUPS, out state $OUTSTATE, run $RUN"
    nothing_installed && echo "(nothing from the kit was found on this machine)"
    read -r -a ports <<<"$(read_ports)"
    say "Step 1: final backup"
    if [[ -e $STATE/hub.db ]]; then
        echo "run $CLI backup (encrypted, into $BACKUPS); if it fails, say so and carry on"
    else
        echo "no database at $STATE/hub.db: no final backup"
    fi
    say "Step 2: stop and disable the units"
    echo "stop and disable edr-hub-backup.timer (and edr-hub-backup.service)"
    echo "cancel the transient units edr-hub-fw-rollback and edr-hub-install"
    echo "stop and disable edr-hub-ui, edr-hub-out, edr-hub (and edr-hub-ca, edr-hub-clients.path, edr-hub-clients.timer, edr-hub-failed)"
    say "Step 3: the firewall table"
    echo "disable edr-hub-nft.service"
    echo "delete only 'table inet edr_hub' (after the services, if the table exists); no other table is touched, nothing is flushed"
    say "Step 4: replay $MANIFEST, last entry first"
    local out
    out=$(parse_manifest) || { echo "could not parse the manifest"; return 3; }
    while IFS=$'\t' read -r tag f1 f2 f3 _ f5; do
        case $tag in
            manifest)
                case $f1 in
                    missing) echo "there is no manifest: nothing is removed from it; known kit paths that exist are printed below" ;;
                    unreadable) echo "the manifest cannot be read" ;;
                esac ;;
            refuse)
                refused=$((refused + 1))
                echo "REFUSE line $f1: $f2" ;;
            entry)
                action=$(classify "$f1" "$f2" "$f3" "$f5")
                describe "$action" "$f1" "$f2" ;;
        esac
    done <<<"$out"
    echo "then: systemctl daemon-reload; stop systemd-journald@edr-hub if its configuration was removed"
    echo "print every kit path still present that the manifest did not remove"
    echo "remove $ETC except $KEEPERS (anything else in it is printed, not deleted)"
    say "Step 5: kept"
    echo "$STATE, $OUTSTATE, $CASTATE (P3), $ETC/secrets.json, $ETC/backup.pass, $BACKUPS and the users $HUB_IDS"
    if [[ $PURGE -eq 1 ]]; then
        say "--purge"
        echo "warn: the CA key is deleted and a backup holds none (offer: edr-hub ca-export first)"
        echo "warn: every enrolled client then needs a new token from a new hub (rehome); old pins will not match"
        echo "warn: the backups are deleted too; copy off anything you want"
        echo "ask twice, then delete $STATE, $OUTSTATE, $CASTATE, $ETC, $BACKUPS, then the users and groups $HUB_IDS"
    fi
    say "Final checks"
    echo "no 'edr_hub' table; nothing listening on ports ${ports[0]}, ${ports[1]} and ${ports[2]}; no edr-hub* unit or process"
    if [[ $refused -gt 0 ]]; then
        echo
        echo "$refused manifest line(s) refused: a real run stops before changing anything (exit 3)."
        return 3
    fi
    return 0
}

if [[ $PLAN -eq 1 ]]; then
    plan
    exit $?
fi

# ---- from here on the script changes things -----------------------------------------------------------

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root (sudo $0)" >&2; exit 3; }

confirm() {   # prompt, expected answer
    local answer
    if [[ $ASSUME_YES -eq 1 ]]; then
        echo "$1 $2 (--yes)"
        return 0
    fi
    [[ -t 0 ]] || { echo "No terminal to ask on; use --yes to go ahead." >&2; return 1; }
    read -rp "$1 " answer
    [[ $answer == "$2" ]]
}

if nothing_installed; then
    echo "Nothing to remove: no hub files, units or data found."
    exit 3
fi

MANIFEST_OUT=$(parse_manifest) || { echo "ERROR: could not parse the manifest" >&2; exit 3; }
if grep -q '^refuse' <<<"$MANIFEST_OUT"; then
    echo "The manifest has lines this script will not act on:" >&2
    grep '^refuse' <<<"$MANIFEST_OUT" | while IFS=$'\t' read -r _ line reason; do echo "  line $line: $reason" >&2; done
    echo "Nothing was changed. Fix or remove those lines in $MANIFEST and run again." >&2
    exit 3
fi
read -r PORT ENROLL_PORT UI_PORT <<<"$(read_ports)"

if [[ $PURGE -eq 0 && $ASSUME_YES -eq 0 ]]; then
    echo "This removes the EDR hub software: its units, firewall table, code and configuration."
    echo "The database, the CA, the server certificate, settings, secrets, backups and users are kept,"
    echo "so install.sh brings the same hub back and enrolled clients keep working."
    confirm "Continue? [y/N]" y || { echo "Aborted"; exit 3; }
fi
if [[ $PURGE -eq 1 ]]; then
    echo "--purge deletes $STATE, $OUTSTATE, $CASTATE, $ETC, $BACKUPS and then the users and groups $HUB_IDS."
    echo
    echo "WARNING 1: the CA key is deleted, and a backup holds none. Run 'edr-hub ca-export' first if you want to keep it."
    echo "WARNING 2: every enrolled client then needs a new token from a new hub (rehome); old pins will not match."
    echo "WARNING 3: the backups in $BACKUPS are deleted too. Copy off anything you want."
    echo
    confirm "Type 'purge' to go on:" purge || { echo "Aborted"; exit 3; }
    confirm "Last chance. Type 'delete everything' to go on:" "delete everything" || { echo "Aborted"; exit 3; }
fi

say "Step 1: final backup"
if [[ -e $STATE/hub.db && -x $CLI ]]; then
    if "$CLI" backup; then
        echo "Final backup written to $BACKUPS"
    else
        echo "The final backup failed (see above). Carrying on."
    fi
else
    echo "No database that can be backed up. Carrying on."
fi

say "Step 2: stopping the units"
systemctl disable --now edr-hub-backup.timer 2>/dev/null || true
systemctl stop edr-hub-backup.service 2>/dev/null || true
systemctl stop edr-hub-fw-rollback.timer edr-hub-fw-rollback.service edr-hub-install.timer edr-hub-install.service 2>/dev/null || true
systemctl reset-failed edr-hub-fw-rollback.service edr-hub-install.service 2>/dev/null || true
for unit in edr-hub-ui edr-hub-out edr-hub edr-hub-ca; do
    systemctl disable --now "$unit.service" 2>/dev/null || true
done
systemctl disable --now edr-hub-clients.path edr-hub-clients.timer 2>/dev/null || true
systemctl stop edr-hub-clients.service edr-hub-failed.service 2>/dev/null || true
echo "Stopped (clients spool and retry meanwhile)"

say "Step 3: firewall table"
systemctl disable --now edr-hub-nft.service 2>/dev/null || true
if command -v nft >/dev/null 2>&1 && nft list table inet edr_hub >/dev/null 2>&1; then
    nft delete table inet edr_hub && echo "Deleted table inet edr_hub"
else
    echo "No inet edr_hub table"
fi

say "Step 4: replaying the manifest"
journal_removed=0
if grep -q $'^manifest\tmissing' <<<"$MANIFEST_OUT"; then
    echo "There is no manifest ($MANIFEST): nothing is removed from it."
fi
while IFS=$'\t' read -r tag kind path prior saved cond; do
    [[ $tag == entry ]] || continue
    action=$(classify "$kind" "$path" "$prior" "$cond")
    case $action in
        REMOVE|REMOVE_EDITED)
            [[ $action == REMOVE_EDITED ]] && echo "NOTE: $path was changed since install."
            rm -f -- "$path" && echo "Removed $path"
            [[ $path == "$JOURNAL_CONF" ]] && journal_removed=1 ;;
        RESTORE)
            if [[ -f $saved ]]; then
                cp -p -- "$saved" "$path" && echo "Put the prior copy back at $path"
            else
                echo "NOTE: the saved prior copy $saved is missing; $path left as it is"
            fi ;;
        RMDIR)
            if rmdir -- "$path" 2>/dev/null; then echo "Removed directory $path"; else echo "Directory $path is not empty or gone: left alone"; fi ;;
        REMOVE_TREE)
            case $path in
                /usr/local/lib/edr-hub|/usr/local/lib/edr-hub.prev) rm -rf -- "$path" && echo "Removed $path" ;;
            esac ;;
        UNIT_OFF)
            systemctl disable --now "$path" 2>/dev/null || true
            systemctl reset-failed "$path" 2>/dev/null || true ;;
        LEAVE_EDITED|LEAVE_NOTFILE|LEAVE_PRESENT|KEEP_ID|PACKAGE)
            describe "$action" "$kind" "$path" ;;
        *) ;;
    esac
done <<<"$(grep -E $'^entry\t' <<<"$MANIFEST_OUT")"
systemctl daemon-reload
if [[ $journal_removed -eq 1 || ! -e $JOURNAL_CONF ]]; then
    systemctl stop systemd-journald@edr-hub.socket systemd-journald@edr-hub.service 2>/dev/null || true
fi

leftovers=$(leftover_paths)
if [[ -n $leftovers ]]; then
    echo
    echo "Still present, not removed (not listed in the manifest, or kept for a reason above):"
    sed 's/^/  /' <<<"$leftovers"
fi
extras=$(etc_extras)
if [[ -n $extras ]]; then
    echo
    echo "In $ETC, not listed in the manifest and left alone:"
    sed 's/^/  /' <<<"$extras"
fi
rm -rf -- "${ETC:?}/prior"
rm -f -- "$MANIFEST"
rmdir -- "$ETC" 2>/dev/null || true

say "Step 5: what stays"
if [[ $PURGE -eq 0 ]]; then
    echo "Kept: $STATE, $OUTSTATE, $CASTATE (if any), $ETC/secrets.json, $ETC/backup.pass, $BACKUPS and the users and groups $HUB_IDS."
    echo "Running install.sh again brings the same hub back. No package was removed."
    echo "A DigitalOcean Cloud Firewall and the DNS or Reserved IP records are yours: remove them by hand."
else
    say "Purging"
    for d in "$STATE" "$OUTSTATE" "$CASTATE" "$ETC" "$BACKUPS"; do
        guard_dir "$d" || { echo "Refusing to delete '$d'"; continue; }
        rm -rf -- "$d" && echo "Deleted $d"
    done
    kept_ids=$(awk -F'\t' '$1 == "entry" && ($2 == "user" || $2 == "group") && $4 == "present" {print $2 " " $3}' <<<"$MANIFEST_OUT")
    for id in $HUB_IDS; do
        if grep -qx "user $id" <<<"$kept_ids"; then
            echo "Kept user $id: it existed before the kit"
        elif id -u "$id" >/dev/null 2>&1; then
            userdel "$id" && echo "Deleted user $id"
        fi
        if grep -qx "group $id" <<<"$kept_ids"; then
            echo "Kept group $id: it existed before the kit"
        elif getent group "$id" >/dev/null 2>&1; then
            groupdel "$id" && echo "Deleted group $id"
        fi
    done
fi

say "Final checks"
fail=0
if command -v nft >/dev/null 2>&1 && nft list table inet edr_hub >/dev/null 2>&1; then
    echo "FAIL: the inet edr_hub table is still loaded"; fail=1
else
    echo "PASS: no edr_hub table"
fi
listening=0
for p in "$PORT" "$ENROLL_PORT" "$UI_PORT"; do
    if command -v ss >/dev/null 2>&1 && [[ -n $(ss -Hltn "sport = :$p" 2>/dev/null) ]]; then
        echo "FAIL: something still listens on port $p"; listening=1
    fi
done
if [[ $listening -eq 0 ]]; then echo "PASS: nothing listens on $PORT, $ENROLL_PORT and $UI_PORT"; else fail=1; fi
units=$({ systemctl list-unit-files --no-legend 'edr-hub*' 2>/dev/null; systemctl list-units --all --no-legend 'edr-hub*' 2>/dev/null; } | awk 'NF {print $1}' | sort -u)
if [[ -n $units ]]; then
    echo "FAIL: edr-hub units remain:"; sed 's/^/  /' <<<"$units"; fail=1
else
    echo "PASS: no edr-hub unit"
fi
if pgrep -f 'edr_hub(_ui|_out)?\.py' >/dev/null 2>&1; then
    echo "FAIL: an edr-hub process is still running"; fail=1
else
    echo "PASS: no edr-hub process"
fi
if [[ $fail -eq 0 ]]; then
    echo; echo "PASS"
    exit 0
fi
echo; echo "FAIL"
exit 2
