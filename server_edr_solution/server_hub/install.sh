#!/bin/bash
# Install or upgrade the EDR hub (server_hub, PLAN.md section 8, 14 and 17). Run as root from the unpacked release.
#
#   sudo ./install.sh [--port 8443] [--enroll-port 8444] [--ui-port 8450]
#                     [--admin-ip CIDR ...] [--public-ip IP ...] [--clients-only]
#                     [--retention-days 30] [--max-db-size 2G] [--ui-host HOST:PORT ...]
#                     [--webhook-ca FILE] [--plan] [--yes] [--force] [--from-checkout]
#   sudo ./install.sh --confirm       from a NEW ssh session, after the firewall step (step 10)
#
# Flags seed /var/lib/edr-hub/settings.json on the first run. A re-run upgrades the code and keeps the CA, the
# database, the tokens and every setting; a flag that is named again changes just that setting (--admin-ip and
# --public-ip replace the whole list). --plan prints every file, unit, user, directory and setting it would write
# and changes nothing. --force only permits a downgrade. Secrets are never flags: edr-hub settings set KEY -.
#
# Exit codes (PLAN section 17): 0 done, 2 failed, 3 refused (pre-flight, nothing changed), 4 failed after changes and
# rolled back (a migration failed, or the firewall rollback fired), 64 usage error.
#
# Safe to re-run. Every change is recorded in /etc/edr-hub/manifest.jsonl BEFORE it is made, which is what
# uninstall.sh replays. It never flushes an nftables table other than the one it owns, never edits UFW (it prints
# the `ufw allow` lines instead), and loads the firewall last, with a 300 s rollback timer when run over SSH.
set -Eeuo pipefail

SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Where things live. The five EDR_HUB_*_DIR variables are for tests and the mock, as in uninstall.sh.
STATE=${EDR_HUB_STATE_DIR:-/var/lib/edr-hub}
RUN=${EDR_HUB_RUN_DIR:-/run/edr-hub}
ETC=${EDR_HUB_ETC_DIR:-/etc/edr-hub}
BACKUPS=${EDR_HUB_BACKUP_DIR:-/var/backups/edr-hub}
OS_RELEASE=${EDR_HUB_OS_RELEASE:-/etc/os-release}
LIB=/usr/local/lib/edr-hub
PREV=/usr/local/lib/edr-hub.prev
CLI=/usr/local/sbin/edr-hub
UNITDIR=/etc/systemd/system
MANIFEST=$ETC/manifest.jsonl
PRIORS=$ETC/prior
CONFIRM_MARK=/run/edr-hub-install.confirmed
INSTALL_LOG=/var/log/edr-hub-install.log
HUB_USERS=(edr-hub edr-hub-ui edr-hub-out)
ENABLE_UNITS=(edr-hub.service edr-hub-out.service edr-hub-ui.service edr-hub-backup.timer)

# What is copied where: source|destination|mode|owner:group. Each source is named in full so that `make dist` can check
# that the tarball holds it.
KIT_FILES=(
    "$SRC/files/edr-hub.service|$UNITDIR/edr-hub.service|0644|root:root"
    "$SRC/files/edr-hub-out.service|$UNITDIR/edr-hub-out.service|0644|root:root"
    "$SRC/files/edr-hub-ui.service|$UNITDIR/edr-hub-ui.service|0644|root:root"
    "$SRC/files/edr-hub-failed.service|$UNITDIR/edr-hub-failed.service|0644|root:root"
    "$SRC/files/edr-hub-backup.service|$UNITDIR/edr-hub-backup.service|0644|root:root"
    "$SRC/files/edr-hub-backup.timer|$UNITDIR/edr-hub-backup.timer|0644|root:root"
    "$SRC/files/edr-hub-nft.service|$UNITDIR/edr-hub-nft.service|0644|root:root"
    "$SRC/files/journald@edr-hub.conf|/etc/systemd/journald@edr-hub.conf|0644|root:root"
    "$SRC/files/52edr-hub|/etc/apt/apt.conf.d/52edr-hub|0644|root:root"
)
# The advisory table: common/ is beside the files in the release tarball and one level up in a checkout
ADVISORIES=$SRC/common/advisories.json
if [[ ! -f $ADVISORIES ]]; then ADVISORIES=$SRC/../common/advisories.json; fi
# Beside the code in /usr/local/lib/edr-hub (re-runs and check.sh use them there)
LIB_EXTRAS=(
    "$SRC/files/render-nft.sh|render-nft.sh"
    "$SRC/files/edr-hub.nft.in|edr-hub.nft.in"
    "$SRC/check.sh|check.sh"
    "$ADVISORIES|advisories.json"
)

# ---- flags ---------------------------------------------------------------------------------------------------
PORT="" ENROLL_PORT="" UI_PORT="" RETENTION="" MAX_DB="" WEBHOOK_CA=""
ADMIN_IPS=() PUBLIC_IPS=() UI_HOSTS=()
PLAN=0 YES=0 FORCE=0 CONFIRM=0 CLIENTS_ONLY=0 FROM_CHECKOUT=0
ORIG_ARGS=("$@")

usage() {
    cat >&2 <<'EOF'
usage: install.sh [--port N] [--enroll-port N] [--ui-port N] [--admin-ip CIDR ...] [--public-ip IP ...]
                  [--retention-days N] [--max-db-size 2G] [--ui-host HOST:PORT ...] [--webhook-ca FILE]
                  [--plan] [--yes] [--force] [--from-checkout]
       install.sh --confirm
  --plan           print what would be written and change nothing (exit 0: would go ahead, 3: refused)
  --yes            do not ask before going ahead
  --force          allow a downgrade (otherwise refused)
  --from-checkout  run from a git checkout: no MANIFEST.sha256 to verify (tests and the mock only)
  --confirm        from a NEW ssh session after the firewall step: cancels the rollback timer, keeps the firewall
EOF
}

bad_usage() { echo "install.sh: $*" >&2; usage; exit 64; }

parse_args() {
    local arg val
    while [[ $# -gt 0 ]]; do
        arg=$1
        val=""
        case $arg in
            --port=*|--enroll-port=*|--ui-port=*|--admin-ip=*|--public-ip=*|--retention-days=*|--max-db-size=*|--ui-host=*|--webhook-ca=*)
                val=${arg#*=}; arg=${arg%%=*}; set -- "$arg" "$val" "${@:2}" ;;
        esac
        case $arg in
            --port|--enroll-port|--ui-port|--admin-ip|--public-ip|--retention-days|--max-db-size|--ui-host|--webhook-ca)
                [[ $# -ge 2 ]] || bad_usage "$arg needs a value"
                val=$2
                shift ;;
        esac
        case $arg in
            --port) check_port "$arg" "$val"; PORT=$val ;;
            --enroll-port) check_port "$arg" "$val"; ENROLL_PORT=$val ;;
            --ui-port) check_port "$arg" "$val"; UI_PORT=$val ;;
            --admin-ip) ADMIN_IPS+=("$(py_norm cidr "$val")") || bad_usage "--admin-ip is not a CIDR: $val" ;;
            --public-ip) PUBLIC_IPS+=("$(py_norm ip "$val")") || bad_usage "--public-ip is not an IP address: $val" ;;
            --retention-days)
                [[ $val =~ ^[0-9]{1,4}$ ]] && ((10#$val >= 1 && 10#$val <= 3650)) || bad_usage "--retention-days must be 1 to 3650"
                RETENTION=$((10#$val)) ;;
            --max-db-size)
                [[ ${val^^} =~ ^[0-9]+[KMG]?$ ]] || bad_usage "--max-db-size must look like 512M or 2G"
                MAX_DB=${val^^} ;;
            --ui-host)
                [[ $val =~ ^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):[0-9]{1,5}$ ]] || bad_usage "--ui-host must be HOST:PORT"
                UI_HOSTS+=("$val") ;;
            --webhook-ca)
                [[ -n $val ]] || bad_usage "--webhook-ca needs a file"
                WEBHOOK_CA=$val ;;
            --clients-only) CLIENTS_ONLY=1 ;;
            --plan) PLAN=1 ;;
            --yes|-y) YES=1 ;;
            --force) FORCE=1 ;;
            --confirm) CONFIRM=1 ;;
            --from-checkout) FROM_CHECKOUT=1 ;;
            -h|--help) usage; exit 0 ;;
            *) bad_usage "unknown option: $arg" ;;
        esac
        shift
    done
    if [[ $CLIENTS_ONLY -eq 1 ]]; then
        bad_usage "--clients-only is not part of this release (it comes with the optional client allow-list)"
    fi
    if [[ $CONFIRM -eq 1 && ( $PLAN -eq 1 || ${#ORIG_ARGS[@]} -gt 1 ) ]]; then
        bad_usage "--confirm takes no other option"
    fi
    if [[ -n $PORT && ( $PORT == "$ENROLL_PORT" || $PORT == "$UI_PORT" ) ]] || [[ -n $ENROLL_PORT && $ENROLL_PORT == "$UI_PORT" ]]; then
        bad_usage "--port, --enroll-port and --ui-port must differ"
    fi
    if [[ -n $WEBHOOK_CA && ! -r $WEBHOOK_CA ]]; then
        bad_usage "--webhook-ca: cannot read $WEBHOOK_CA"
    fi
}

check_port() {
    [[ $2 =~ ^[0-9]{1,5}$ ]] && ((10#$2 >= 1 && 10#$2 <= 65535)) || bad_usage "$1 must be a port number (1 to 65535)"
}

# ---- read-only helpers (the plan uses all of them) -------------------------------------------------------------
say() { printf '\n==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
fatal() { echo "ERROR: $*" >&2; exit 2; }

REFUSE=() WARN=()
refuse() { REFUSE+=("$*"); }
warn() { WARN+=("$*"); }

# One address or network, normalised (IPv4-mapped IPv6 becomes IPv4). Exit 1 when it is neither.
py_norm() {   # ip|cidr VALUE
    python3 -I - "$1" "$2" <<'PY'
import ipaddress, sys
kind, value = sys.argv[1:3]
try:
    if len(value) > 49 or value != value.strip() or "%" in value:
        raise ValueError(value)
    if kind == "ip":
        ip = ipaddress.ip_address(value)
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        print(ip)
    else:
        print(ipaddress.ip_network(value, strict=False))
except ValueError:
    sys.exit(1)
PY
}

# A value from settings.json (a list comes out comma-separated); nothing when the file is missing or unreadable.
stored_setting() {   # KEY
    [[ -r $STATE/settings.json ]] || return 0
    python3 -I - "$STATE/settings.json" "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        v = json.load(f).get(sys.argv[2])
except (OSError, ValueError, AttributeError):
    sys.exit(0)
if isinstance(v, list):
    print(",".join(str(x) for x in v))
elif v is not None and not isinstance(v, dict):
    print(v)
PY
}

code_value() {   # FILE REGEX-NAME : the value of NAME = "x" or NAME = 3 in a Python file
    { sed -n "s/^$2 *= *\"\{0,1\}\([^\"]*\)\"\{0,1\}.*/\1/p" "$1" 2>/dev/null || true; } | head -n 1
}

size_bytes() {   # 512M -> bytes
    local v=${1^^} n unit=1
    n=${v%[KMG]}
    case $v in *K) unit=1024 ;; *M) unit=1048576 ;; *G) unit=1073741824 ;; esac
    echo $((10#$n * unit))
}

add_unique() {   # ARRAY-NAME VALUE
    local -n arr=$1
    local x
    for x in "${arr[@]}"; do
        [[ $x == "$2" ]] && return 0
    done
    arr+=("$2")
}

# The client address of the ssh session this runs in, also under sudo (which drops SSH_CONNECTION: its parent still has it)
ssh_connection() {
    local conn=${SSH_CONNECTION:-}
    if [[ -z $conn && -n ${SUDO_USER:-} && -r /proc/$PPID/environ ]]; then
        conn=$(tr '\0' '\n' </proc/$PPID/environ 2>/dev/null | sed -n 's/^SSH_CONNECTION=//p' | head -n 1) || conn=""
    fi
    printf '%s' "$conn"
}

ssh_ports() {
    local out=""
    if command -v sshd >/dev/null 2>&1; then
        out=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}') || out=""
    fi
    printf '%s' "$out"
}

# Global addresses of this machine (public, VPC), without container and tunnel interfaces
detect_addresses() {
    command -v ip >/dev/null 2>&1 || return 0
    ip -o addr show scope global 2>/dev/null | awk '
        { if ($2 ~ /^(lo|docker|br-|veth|virbr|cni|flannel|tailscale|wg)/) next
          if ($3 != "inet" && $3 != "inet6") next
          split($4, a, "/"); print a[1] }'
}

free_bytes() {
    local d=$STATE
    if [[ -n ${EDR_HUB_DF_BYTES:-} ]]; then echo "$EDR_HUB_DF_BYTES"; return 0; fi
    while [[ ! -d $d && $d != / ]]; do d=$(dirname "$d"); done
    df -B1 --output=avail "$d" 2>/dev/null | tail -n 1 | tr -d ' '
}

unit_enabled() { systemctl is-enabled --quiet "$1" 2>/dev/null; }
package_present() { [[ $(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null || true) == installed ]]; }

verify_tree() {
    TREE_STATE=""
    if [[ -f $SRC/MANIFEST.sha256 ]]; then
        if (cd "$SRC" && sha256sum -c --quiet MANIFEST.sha256 >/dev/null 2>&1); then
            TREE_STATE="verified against MANIFEST.sha256"
        else
            refuse "the files in $SRC do not match MANIFEST.sha256: unpack the release again and compare its tarball hash with the .sha256 file"
        fi
    elif [[ $FROM_CHECKOUT -eq 1 ]]; then
        TREE_STATE="a checkout: nothing to verify (--from-checkout)"
    else
        refuse "there is no MANIFEST.sha256 in $SRC: run this from the unpacked release tarball (--from-checkout is for tests and the mock)"
    fi
}

# ---- what the run will use -------------------------------------------------------------------------------------
FINAL_PUBLIC=() FINAL_ADMIN=() DETECTED=() STORED_PUBLIC=() STORED_ADMIN=()
SSH_CONN="" SSH_SRC="" OVER_SSH=0 SSH_PORT=22 FIRST_RUN=1 MIGRATING=0 INSTALLED_VERSION="" NEW_VERSION=""
PUBLIC_REPLACE=0 ADMIN_REPLACE=0 JOINED_SSH=0
EFF_PORT=8443 EFF_ENROLL=8444 EFF_UI=8450 EFF_MAX_DB=2G EFF_KEEP=14

compute_settings() {
    local ip v
    [[ -f $STATE/settings.json ]] && FIRST_RUN=0
    v=$(stored_setting port); EFF_PORT=${PORT:-${v:-8443}}
    v=$(stored_setting enroll_port); EFF_ENROLL=${ENROLL_PORT:-${v:-8444}}
    v=$(stored_setting ui_port); EFF_UI=${UI_PORT:-${v:-8450}}
    v=$(stored_setting max_db_size); EFF_MAX_DB=${MAX_DB:-${v:-2G}}
    v=$(stored_setting backup_keep); EFF_KEEP=${v:-14}
    IFS=, read -r -a STORED_PUBLIC <<<"$(stored_setting public_ip)"
    IFS=, read -r -a STORED_ADMIN <<<"$(stored_setting admin_ip)"
    # public_ip: what was found on this machine plus each --public-ip; a re-run without the flag keeps the stored list
    while IFS= read -r ip; do
        [[ -n $ip ]] && add_unique DETECTED "$(py_norm ip "$ip" 2>/dev/null || true)"
    done < <(detect_addresses)
    if [[ ${#PUBLIC_IPS[@]} -gt 0 || ${#STORED_PUBLIC[@]} -eq 0 ]]; then
        PUBLIC_REPLACE=1
        for ip in "${DETECTED[@]}" "${PUBLIC_IPS[@]}"; do [[ -n $ip ]] && add_unique FINAL_PUBLIC "$ip"; done
    else
        FINAL_PUBLIC=("${STORED_PUBLIC[@]}")
    fi
    # admin_ip: the flags (replacing the stored list) or the stored list, and the source of this ssh session
    if [[ ${#ADMIN_IPS[@]} -gt 0 ]]; then
        ADMIN_REPLACE=1
        FINAL_ADMIN=("${ADMIN_IPS[@]}")
    elif [[ ${#STORED_ADMIN[@]} -gt 0 ]]; then
        FINAL_ADMIN=("${STORED_ADMIN[@]}")
    fi
    SSH_CONN=$(ssh_connection)
    if [[ -n $SSH_CONN ]]; then
        OVER_SSH=1
        SSH_SRC=$(py_norm cidr "${SSH_CONN%% *}" 2>/dev/null || true)
        if [[ -n $SSH_SRC ]]; then
            JOINED_SSH=1
            add_unique FINAL_ADMIN "$SSH_SRC"
        fi
    fi
    local ports
    ports=$(ssh_ports)
    SSH_PORT=${ports%%$'\n'*}
    SSH_PORT=${SSH_PORT:-22}
    if [[ $(wc -w <<<"$ports") -gt 1 ]]; then
        warn "sshd listens on more than one port ($(tr '\n' ' ' <<<"$ports")): the firewall opens $SSH_PORT only for the admin addresses"
    fi
    if [[ ${#FINAL_ADMIN[@]} -gt 0 ]]; then
        SETTLED_ADMIN=$(IFS=,; echo "${FINAL_ADMIN[*]}")
    else
        SETTLED_ADMIN=""
    fi
    SETTLED_STORED_ADMIN=$(IFS=,; echo "${STORED_ADMIN[*]:-}")
}

# ---- pre-flight (step 1): collects refusals and warnings; changes nothing -----------------------------------------
preflight() {
    local id="" ver="" ok need avail cap

    # shellcheck source=/dev/null
    if [[ -r $OS_RELEASE ]]; then id=$(. "$OS_RELEASE" && printf '%s' "${ID:-}"); ver=$(. "$OS_RELEASE" && printf '%s' "${VERSION_ID:-}"); fi
    if [[ $id != ubuntu || ( $ver != 24.04 && $ver != 26.04 ) ]]; then
        refuse "this installer supports Ubuntu 24.04 and 26.04 (found: ${id:-unknown} ${ver:-})"
    fi
    [[ -d /run/systemd/system ]] || refuse "systemd is not the running init system"
    if command -v python3 >/dev/null 2>&1; then
        python3 -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' || refuse "python3 3.12 or newer is required"
        python3 -I -c 'import sqlite3, sys; sys.exit(0 if sqlite3.sqlite_version_info >= (3, 27, 0) else 1)' \
            || refuse "SQLite 3.27 or newer (VACUUM INTO) is required"
    else
        refuse "python3 is not installed"
    fi
    if command -v openssl >/dev/null 2>&1; then
        [[ $(openssl version 2>/dev/null | awk '{print $2}') =~ ^[3-9]\. ]] || refuse "openssl 3.0 or newer is required"
    else
        refuse "openssl is not installed"
    fi
    command -v nft >/dev/null 2>&1 || refuse "nftables is not installed (apt install nftables)"
    for ok in useradd groupadd systemd-run systemctl install sha256sum find df; do
        command -v "$ok" >/dev/null 2>&1 || refuse "the command $ok is missing"
    done
    command -v runuser >/dev/null 2>&1 || command -v setpriv >/dev/null 2>&1 || refuse "neither runuser nor setpriv is installed"

    # the tree itself
    local row src
    for row in "${KIT_FILES[@]}" "${LIB_EXTRAS[@]}"; do
        src=${row%%|*}
        [[ -f $src ]] || refuse "the release is incomplete: $src is missing"
    done
    for src in "$SRC/hub/edr_hub.py" "$SRC/hub/hub_common.py" "$SRC/hub/hub_schema.py" "$SRC/pki/strict/ca.ext" "$SRC/hub/agent-hashes.json"; do
        [[ -f $src ]] || refuse "the release is incomplete: $src is missing"
    done

    # the clock: tokens and certificate dates depend on it
    if command -v timedatectl >/dev/null 2>&1; then
        case $(timedatectl show -p NTPSynchronized --value 2>/dev/null || true) in
            yes) ;;
            no) refuse "the clock is not synchronised (timedatectl): tokens and certificates depend on it" ;;
            *) warn "could not tell whether the clock is synchronised" ;;
        esac
    else
        warn "timedatectl is not available: the clock was not checked"
    fi

    # ports
    [[ $EFF_PORT != "$SSH_PORT" && $EFF_ENROLL != "$SSH_PORT" ]] || refuse "the fleet or enrollment port equals the ssh port ($SSH_PORT)"

    # addresses: hub_addresses is capped at 4
    if [[ ${#FINAL_PUBLIC[@]} -eq 0 ]]; then
        refuse "no public address of this machine was found: pass --public-ip IP (a Reserved IP is never found)"
    elif [[ ${#FINAL_PUBLIC[@]} -gt 4 ]]; then
        refuse "the hub would have ${#FINAL_PUBLIC[@]} addresses (${FINAL_PUBLIC[*]}); hub_addresses holds at most 4"
    fi
    if [[ $FIRST_RUN -eq 1 && ${#PUBLIC_IPS[@]} -eq 0 ]]; then
        warn "no --public-ip given: a Reserved IP is not on the NIC and is never found. Pass it, so a replacement hub in the same region can take it over"
    fi

    # disk: the database cap plus backup_keep backups of that size
    cap=$(size_bytes "$EFF_MAX_DB")
    need=$((cap * (1 + EFF_KEEP)))
    avail=$(free_bytes)
    if [[ $avail =~ ^[0-9]+$ ]]; then
        if ((avail < need)); then
            refuse "free disk is $((avail / 1048576)) MiB; the database cap plus $EFF_KEEP backups needs $((need / 1048576)) MiB"
        elif ((avail < 2 * need)); then
            warn "free disk is $((avail / 1048576)) MiB, under twice the $((need / 1048576)) MiB the database cap and $EFF_KEEP backups can use"
        fi
    else
        warn "could not read the free disk space"
    fi

    # warnings
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^status: active'; then
        warn "ufw is active and a drop there still wins over the table below. This installer never edits ufw; run: ufw allow $EFF_PORT/tcp; ufw allow $EFF_ENROLL/tcp"
    fi
    if [[ -n ${SUDO_USER:-} ]] && command -v passwd >/dev/null 2>&1; then
        case $(passwd -S "$SUDO_USER" 2>/dev/null | awk '{print $2}' || true) in
            L|NP) warn "the admin account $SUDO_USER has no local password: the DigitalOcean Recovery Console needs one" ;;
        esac
    fi
    if [[ ${#FINAL_ADMIN[@]} -eq 0 ]]; then
        warn "no admin address at all: SSH stays open to everyone (the firewall file will say so). Pass --admin-ip CIDR"
    fi

    # an existing install: downgrade, schema, a foreign CLI
    NEW_VERSION=$(code_value "$SRC/hub/hub_common.py" VERSION)
    INSTALLED_VERSION=$(code_value "$LIB/hub_common.py" VERSION)
    if [[ -n $INSTALLED_VERSION && -n $NEW_VERSION && $INSTALLED_VERSION != "$NEW_VERSION" ]]; then
        if [[ $(printf '%s\n%s\n' "$INSTALLED_VERSION" "$NEW_VERSION" | sort -V | head -n 1) == "$NEW_VERSION" && $FORCE -eq 0 ]]; then
            refuse "this is version $NEW_VERSION and $INSTALLED_VERSION is installed: a downgrade needs --force (and a restore of the database, section 17)"
        fi
    fi
    if [[ -e $CLI || -L $CLI ]] && [[ $(readlink "$CLI" 2>/dev/null || true) != "$LIB/edr-hub" ]]; then
        refuse "$CLI exists and is not the kit's link: move it away first"
    fi
    MIGRATING=0
    if [[ -f $STATE/hub.db && -r $STATE/hub.db ]]; then
        local have want
        want=$(code_value "$SRC/hub/hub_schema.py" SCHEMA_VERSION)
        have=$(python3 -I - "$STATE/hub.db" <<'PY' 2>/dev/null || true
import sqlite3, sys
try:
    c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True, timeout=5)
    print(c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0])
except Exception:
    pass
PY
)
        if [[ $have =~ ^[0-9]+$ && $want =~ ^[0-9]+$ ]]; then
            if ((have > want)); then
                refuse "hub.db is schema $have and this release knows $want: the hub refuses a database newer than its code (section 17)"
            elif ((have < want)); then
                MIGRATING=1
            fi
        fi
    fi
}

# ---- --plan: print and stop; nothing above or in this function changes anything ----------------------------------------
plan_row() {   # STATUS TEXT
    printf '  %-8s %s\n' "[$1]" "$2"
}

plan_path() {   # LABEL PATH
    if [[ -e $2 || -L $2 ]]; then plan_row "there" "$1"; else plan_row "new" "$1"; fi
}

plan_copy() {   # source dest
    if [[ ! -e $2 ]]; then plan_row "new" "$2"
    elif cmp -s "$1" "$2"; then plan_row "there" "$2 (identical)"
    else plan_row "there" "$2 (differs: the kit's copy is saved first, then replaced)"; fi
}

plan_setting() {   # KEY NEW-VALUE-OR-EMPTY KEPT-VALUE
    if [[ -n $2 ]]; then printf '  %-8s %s = %s\n' "[named]" "$1" "$2"
    elif [[ $FIRST_RUN -eq 1 ]]; then printf '  %-8s %s = %s (default)\n' "[new]" "$1" "${3:-30}"
    else printf '  %-8s %s = %s (kept)\n' "[there]" "$1" "$3"; fi
}

plan() {
    local row src dest mode own u tmp rc=0
    echo "install.sh --plan: nothing is changed."
    echo "Release $SRC (${NEW_VERSION:-unknown version}); $TREE_STATE"
    if [[ -n $INSTALLED_VERSION ]]; then echo "Installed: version $INSTALLED_VERSION (a re-run upgrades; the previous code is kept in $PREV)"; else echo "Installed: nothing (a first install)"; fi
    if [[ $MIGRATING -eq 1 ]]; then echo "The database schema is older than this release's: an encrypted backup is taken first and the hub migrates at start (a failure rolls the code back, exit 4)."; fi
    if [[ $OVER_SSH -eq 1 ]]; then
        echo "Run over SSH: it would re-run itself under systemd-run --unit=edr-hub-install, join ${SSH_SRC:-your address} to the admin list, and arm the 300 s rollback timer."
    else
        echo "Not over SSH: no rollback timer; edr-hub-nft.service is enabled at once."
    fi

    say "Step 1: pre-flight"
    for row in "${REFUSE[@]}"; do plan_row "REFUSED" "$row"; done
    for row in "${WARN[@]}"; do plan_row "warning" "$row"; done
    if [[ ${#REFUSE[@]} -eq 0 && ${#WARN[@]} -eq 0 ]]; then plan_row "ok" "every check passed"; fi
    if [[ ${#REFUSE[@]} -eq 0 ]]; then plan_row "ok" "Ubuntu, systemd, python3, openssl, nftables and SQLite are as required"; fi

    say "Step 2: users and directories"
    for u in "${HUB_USERS[@]}"; do
        if getent passwd "$u" >/dev/null 2>&1; then plan_row "there" "user and group $u"; else plan_row "new" "system user and group $u (nologin)"; fi
    done
    plan_path "$STATE (edr-hub:edr-hub-ui 2750)" "$STATE"
    plan_path "$STATE/ca (edr-hub 0700)" "$STATE/ca"
    plan_path "$STATE/tls (edr-hub 0700)" "$STATE/tls"
    plan_path "$BACKUPS (root 0700)" "$BACKUPS"
    plan_path "$ETC (root 0750)" "$ETC"
    plan_path "$MANIFEST (every change, written before it is made)" "$MANIFEST"
    plan_path "$ETC/secrets.json (root 0600, {} at first)" "$ETC/secrets.json"
    plan_path "$ETC/backup.pass (root 0600, generated once and shown once)" "$ETC/backup.pass"
    echo "  /var/lib/edr-hub-out and /run/edr-hub are made by the units themselves."

    say "Step 3: code, CA and certificates"
    if [[ -d $LIB ]]; then plan_row "there" "$LIB (replaced; the old copy moves to $PREV)"; else plan_row "new" "$LIB (root-owned copy of hub/, pki/strict/, advisories.json, render-nft.sh, edr-hub.nft.in, check.sh)"; fi
    plan_path "$CLI -> $LIB/edr-hub" "$CLI"
    plan_path "$STATE/ca/ca.pem and ca.key (EC P-384, 10 years; kept if present)" "$STATE/ca/ca.pem"
    plan_path "$STATE/tls/server.pem and server.key (EC P-256, IP SANs: ${FINAL_PUBLIC[*]:-none})" "$STATE/tls/server.pem"
    echo "  made by: python3 -I $LIB/edr_hub.py --init-only, run as user edr-hub; then openssl verify -x509_strict; the CA SHA-256 is printed"
    echo "  Settings in $STATE/settings.json:"
    plan_setting port "$PORT" "$EFF_PORT"
    plan_setting enroll_port "$ENROLL_PORT" "$EFF_ENROLL"
    plan_setting ui_port "$UI_PORT" "$EFF_UI"
    plan_setting public_ip "$([[ $PUBLIC_REPLACE -eq 1 ]] && IFS=, && echo "${FINAL_PUBLIC[*]}")" "$(IFS=,; echo "${FINAL_PUBLIC[*]:-}")"
    plan_setting admin_ip "$([[ ${ADMIN_REPLACE:-0} -eq 1 || $JOINED_SSH -eq 1 ]] && echo "$SETTLED_ADMIN")" "${SETTLED_ADMIN:-none}"
    plan_setting retention_days "$RETENTION" "$(stored_setting retention_days)"
    plan_setting max_db_size "$MAX_DB" "$EFF_MAX_DB"
    plan_setting ui_host "$(IFS=,; echo "${UI_HOSTS[*]:-}")" "the loopback names with ui_port"
    plan_setting webhook_ca "$([[ -n $WEBHOOK_CA ]] && echo "$STATE/webhook-ca.pem")" "unset"
    if [[ $JOINED_SSH -eq 1 ]]; then echo "  The source of your ssh session, $SSH_SRC, joins the admin list."; fi
    if [[ -n $WEBHOOK_CA ]]; then plan_copy "$WEBHOOK_CA" "$STATE/webhook-ca.pem"; fi

    say "Step 4: units"
    for row in "${KIT_FILES[@]}"; do
        IFS='|' read -r src dest mode own <<<"$row"
        plan_copy "$src" "$dest"
    done
    echo "  then systemctl daemon-reload"

    say "Step 5: firewall rules (written now, loaded last)"
    tmp=$(mktemp -d)
    if render_nft "$tmp/edr-hub.nft" 2>"$tmp/err"; then
        plan_copy "$tmp/edr-hub.nft" "$ETC/edr-hub.nft"
        echo "  table inet edr_hub: ports $EFF_PORT and $EFF_ENROLL, ssh $SSH_PORT from ${SETTLED_ADMIN:-anywhere (no admin address)}; checked with nft -c -f before anything starts"
    else
        plan_row "REFUSED" "the firewall file would not render: $(head -n 1 "$tmp/err")"
        rc=3
    fi
    rm -rf "$tmp"

    say "Step 6: updates and reboots"
    plan_copy "$SRC/files/52edr-hub" /etc/apt/apt.conf.d/52edr-hub
    if package_present unattended-upgrades; then plan_row "there" "package unattended-upgrades"; else plan_row "new" "package unattended-upgrades (apt-get install)"; fi
    plan_copy "$SRC/files/journald@edr-hub.conf" /etc/systemd/journald@edr-hub.conf

    say "Step 7: dead-man ping"
    echo "  optional, off: edr-hub settings set deadman_url -"

    say "Step 8: scheduled backups"
    echo "  edr-hub-backup.timer (daily 02:15 UTC) enabled; backup.pass generated if absent; run edr-hub ca-export once"

    say "Step 9: start"
    echo "  systemctl enable and restart edr-hub, edr-hub-out, edr-hub-ui; wait for edr-hub health"
    if [[ $MIGRATING -eq 1 ]]; then echo "  before the swap: edr-hub backup (a failure stops here, exit 3, nothing changed)"; fi

    say "Step 10: apply the firewall, then confirm"
    echo "  nft -c -f $ETC/edr-hub.nft, then nft -f $ETC/edr-hub.nft; nothing is ever flushed"
    if [[ $OVER_SSH -eq 1 ]]; then
        echo "  arm: systemd-run --on-active=300 --unit=edr-hub-fw-rollback nft delete table inet edr_hub"
        echo "  from a NEW ssh session: sudo $SRC/install.sh --confirm  (within 300 s; it cancels the timer, then enables edr-hub-nft.service)"
        echo "  if the timer fires first: the table is gone and the installer exits 4"
    else
        echo "  no timer (no ssh session): edr-hub-nft.service is enabled at once"
    fi
    echo "  then check.sh, the base dashboard URL in $ETC/ui-url, the CA SHA-256 and the first commands"

    echo
    if [[ ${#REFUSE[@]} -gt 0 || $rc -ne 0 ]]; then
        echo "${#REFUSE[@]} pre-flight refusal(s): a real run changes nothing and exits 3."
        return 3
    fi
    echo "Pre-flight passed: a real run would go ahead."
    return 0
}

# Render the firewall file from the release's template into $1
render_nft() {
    local a4=() a6=() ip
    for ip in "${FINAL_ADMIN[@]}"; do
        if [[ $ip == *:* ]]; then a6+=("$ip"); else a4+=("$ip"); fi
    done
    bash "$SRC/files/render-nft.sh" --port "$EFF_PORT" --enroll-port "$EFF_ENROLL" --ssh-port "$SSH_PORT" \
        --admin4 "$(IFS=,; echo "${a4[*]:-}")" --admin6 "$(IFS=,; echo "${a6[*]:-}")" --hub-user edr-hub \
        --template "$SRC/files/edr-hub.nft.in" >"$1"
}

# ---- from here on the script changes things: main() reaches nothing below before the --plan gate ----------------------

# Every change to the system goes through run(), put_file(), put_kept() or manifest_add(); tests replace run().
run() { "$@"; }

WORK=""
BACKUP_PASS="" BACKUP_PASS_NEW=0 STAGE="" TEE_PID="" CA_SHA="" BACKUP_FILE=""

cleanup() {
    if [[ -n $STAGE && -d $STAGE ]]; then run rm -rf -- "${STAGE:?}"; fi
    if [[ -n $WORK && -d $WORK ]]; then rm -rf -- "${WORK:?}"; fi
    return 0
}

on_error() {
    local rc=$1 line=$2
    trap - ERR
    echo "ERROR: the install failed at line $line (exit $rc). Whatever was done above stays; it is safe to run install.sh again." >&2
    exit 2
}

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

# One line of the manifest, written before the change it describes.
#   manifest_add KIND PATH PRIOR [SHA256]      PRIOR: absent | present | saved:/etc/edr-hub/prior/NAME
manifest_add() {
    local kind=$1 path=$2 prior=$3 sha=${4:-} pj line
    [[ $kind =~ ^(file|dir|unit|user|group|package|link)$ ]] || fatal "manifest: bad kind $kind"
    [[ $path =~ ^[A-Za-z0-9._@+:/-]+$ ]] || fatal "manifest: bad path $path"
    case $prior in
        absent|present) pj="\"$prior\"" ;;
        saved:/*) pj="{\"saved\": \"${prior#saved:}\"}" ;;
        *) fatal "manifest: bad prior $prior" ;;
    esac
    line="{\"ts\": $(date +%s), \"kind\": \"$kind\", \"path\": \"$path\", \"prior\": $pj"
    if [[ -n $sha ]]; then
        [[ $sha =~ ^[0-9a-f]{64}$ ]] || fatal "manifest: bad sha256"
        line+=", \"sha256\": \"$sha\""
    fi
    (umask 077; printf '%s}\n' "$line" >>"$MANIFEST")
}

manifest_seen() { [[ -f $MANIFEST ]] && grep -qF "\"path\": \"$1\"" "$MANIFEST"; }

# What was there before the kit touched it. A foreign file is copied to /etc/edr-hub/prior first.
prior_for() {   # KIND PATH
    local name
    case $1 in
        file)
            if manifest_seen "$2"; then echo present
            elif [[ -e $2 || -L $2 ]]; then
                name=${2//\//_}; name=${name#_}
                run install -d -m 0700 -o root -g root "$PRIORS"
                run cp -p -- "$2" "$PRIORS/$name"
                echo "saved:$PRIORS/$name"
            else echo absent; fi ;;
        dir|link) if [[ -e $2 || -L $2 ]]; then echo present; else echo absent; fi ;;
        unit) if unit_enabled "$2"; then echo present; else echo absent; fi ;;
        user) if getent passwd "$2" >/dev/null 2>&1; then echo present; else echo absent; fi ;;
        group) if getent group "$2" >/dev/null 2>&1; then echo present; else echo absent; fi ;;
        package) if package_present "$2"; then echo present; else echo absent; fi ;;
    esac
}

record() {   # KIND PATH [SHA256]
    manifest_add "$1" "$2" "$(prior_for "$1" "$2")" "${3:-}"
}

# Copy a file of the kit: manifest line first, then the change.
put_file() {   # SOURCE DEST MODE OWNER:GROUP
    record file "$2" "$(sha256_of "$1")"
    run install -m "$3" -o "${4%%:*}" -g "${4##*:}" "$1" "$2"
}

# A file the operator keeps across uninstall (secrets.json, backup.pass, the webhook CA): not in the manifest.
put_kept() {   # DEST MODE OWNER:GROUP   (content on stdin)
    local tmp
    tmp=$(mktemp "$WORK/kept.XXXXXX")
    cat >"$tmp"
    run install -m "$2" -o "${3%%:*}" -g "${3##*:}" "$tmp" "$1"
}

put_text() {   # DEST MODE OWNER:GROUP   (content on stdin; recorded)
    local tmp
    tmp=$(mktemp "$WORK/text.XXXXXX")
    cat >"$tmp"
    put_file "$tmp" "$1" "$2" "$3"
}

run_as_hub() {
    if command -v runuser >/dev/null 2>&1; then
        run runuser -u edr-hub -- "$@"
    else
        run setpriv --reuid=edr-hub --regid=edr-hub --init-groups -- "$@"
    fi
}

# ---- the steps --------------------------------------------------------------------------------------------------------
step_etc() {
    if [[ ! -d $ETC ]]; then
        # The manifest lives here, so the directory is made first and its line follows at once
        run install -d -m 0750 -o root -g root "$ETC"
        manifest_add dir "$ETC" absent
    else
        manifest_add dir "$ETC" present
        run chmod 0750 "$ETC"
    fi
    run install -d -m 0700 -o root -g root "$PRIORS"
}

migration_backup() {
    say "Before the swap: the schema changes, so an encrypted backup is taken first"
    if [[ -x $CLI ]] && "$CLI" backup; then
        BACKUP_FILE=$(ls -t "$BACKUPS" 2>/dev/null | head -n 1 || true)
        echo "Backup written: $BACKUPS/$BACKUP_FILE"
    else
        echo "ERROR: the backup failed; nothing has been changed (section 17)." >&2
        exit 3
    fi
}

step_users() {
    local u
    say "Step 2: users and directories"
    step_etc          # first: the manifest lives in it, and every record below writes a line there
    for u in "${HUB_USERS[@]}"; do
        if ! getent passwd "$u" >/dev/null 2>&1; then
            record group "$u"
            record user "$u"
            if getent group "$u" >/dev/null 2>&1; then
                run useradd --system --gid "$u" --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$u"
            else
                run useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$u"
            fi
            echo "Created user $u"
        else
            record user "$u"
            record group "$u"
            echo "User $u exists"
        fi
    done
    # /var/lib/edr-hub: edr-hub:edr-hub-ui 2750, so files inherit the group the dashboard reads with
    run install -d -m 0750 -o edr-hub -g edr-hub-ui "$STATE"
    run chmod 2750 "$STATE"
    run install -d -m 0700 -o edr-hub -g edr-hub "$STATE/ca"
    run install -d -m 0700 -o edr-hub -g edr-hub "$STATE/tls"
    run install -d -m 0700 -o root -g root "$BACKUPS"
    if [[ ! -e $ETC/secrets.json ]]; then
        printf '{}\n' | put_kept "$ETC/secrets.json" 0600 root:root
        echo "Created $ETC/secrets.json (empty; edr-hub settings set KEY - fills it)"
    fi
    if [[ ! -e $ETC/backup.pass ]]; then
        BACKUP_PASS=$(openssl rand -base64 36)
        printf '%s\n' "$BACKUP_PASS" | put_kept "$ETC/backup.pass" 0600 root:root
        BACKUP_PASS_NEW=1
    fi
}

step_code() {
    local row src name
    say "Step 3: code, CA and certificates"
    STAGE=/usr/local/lib/.edr-hub-stage.$$
    run rm -rf -- "${STAGE:?}"
    run mkdir -p -- "$STAGE"
    run cp -a -- "$SRC/hub/." "$STAGE/"
    run cp -a -- "$SRC/pki" "$STAGE/pki"
    for row in "${LIB_EXTRAS[@]}"; do
        src=${row%%|*}; name=${row##*|}
        run cp -- "$src" "$STAGE/$name"
    done
    if [[ -f $SRC/VERSION ]]; then run cp -- "$SRC/VERSION" "$STAGE/VERSION"; fi
    run chown -R root:root "$STAGE"
    run find "$STAGE" -type d -exec chmod 0755 {} +
    run find "$STAGE" -type f -exec chmod 0644 {} +
    run chmod 0755 "$STAGE/edr-hub" "$STAGE/render-nft.sh" "$STAGE/check.sh"
    # The previous copy is kept once (section 17); the swap itself is two renames
    record dir "$LIB"
    if [[ -d $LIB ]]; then
        record dir "$PREV"
        run rm -rf -- "${PREV:?}"
        run mv -- "$LIB" "$PREV"
    fi
    run mv -- "$STAGE" "$LIB"
    STAGE=""
    record link "$CLI"
    run ln -sfn "$LIB/edr-hub" "$CLI"
    echo "Code is in $LIB, the CLI is $CLI"
}

step_init() {
    local args ip
    if [[ -n $WEBHOOK_CA ]]; then
        python3 -I - "$WEBHOOK_CA" <<'PY' >/dev/null || fatal "--webhook-ca is not a PEM certificate"
import ssl, sys
with open(sys.argv[1], encoding="ascii") as f:
    ssl.PEM_cert_to_DER_cert(f.read().strip() + "\n")
PY
        put_kept "$STATE/webhook-ca.pem" 0644 edr-hub:edr-hub-ui <"$WEBHOOK_CA"
    fi
    args=(--init-only --state-dir "$STATE" --etc-dir "$ETC" --run-dir "$RUN")
    if [[ -n $PORT ]]; then args+=(--port "$PORT"); fi
    if [[ -n $ENROLL_PORT ]]; then args+=(--enroll-port "$ENROLL_PORT"); fi
    if [[ -n $UI_PORT ]]; then args+=(--ui-port "$UI_PORT"); fi
    if [[ -n $RETENTION ]]; then args+=(--retention-days "$RETENTION"); fi
    if [[ -n $MAX_DB ]]; then args+=(--max-db-size "$MAX_DB"); fi
    if [[ $PUBLIC_REPLACE -eq 1 ]]; then
        for ip in "${FINAL_PUBLIC[@]}"; do args+=(--public-ip "$ip"); done
    fi
    if [[ ${#FINAL_ADMIN[@]} -gt 0 && ( $ADMIN_REPLACE -eq 1 || $SETTLED_ADMIN != "$SETTLED_STORED_ADMIN" ) ]]; then
        for ip in "${FINAL_ADMIN[@]}"; do args+=(--admin-ip "$ip"); done
    fi
    for ip in "${UI_HOSTS[@]}"; do args+=(--ui-host "$ip"); done
    if [[ -n $WEBHOOK_CA ]]; then args+=(--webhook-ca-path "$STATE/webhook-ca.pem"); fi
    run_as_hub "$(command -v python3)" -I "$LIB/edr_hub.py" "${args[@]}"
    EFF_PORT=$(stored_setting port); EFF_ENROLL=$(stored_setting enroll_port); EFF_UI=$(stored_setting ui_port)
    EFF_PORT=${EFF_PORT:-8443}; EFF_ENROLL=${EFF_ENROLL:-8444}; EFF_UI=${EFF_UI:-8450}
    openssl verify -x509_strict -no-CApath -no-CAstore -CAfile "$STATE/ca/ca.pem" "$STATE/ca/ca.pem"
    openssl verify -x509_strict -no-CApath -no-CAstore -CAfile "$STATE/ca/ca.pem" -purpose sslserver "$STATE/tls/server.pem"
    CA_SHA=$(openssl x509 -in "$STATE/ca/ca.pem" -outform DER | sha256sum | cut -d' ' -f1)
    echo "CA certificate SHA-256: $CA_SHA"
    echo "Server certificate: $(openssl x509 -in "$STATE/tls/server.pem" -noout -ext subjectAltName 2>/dev/null | tr -d '\n' | sed 's/  */ /g')"
}

step_units() {
    local row src dest mode own
    say "Step 4: units"
    for row in "${KIT_FILES[@]}"; do
        IFS='|' read -r src dest mode own <<<"$row"
        put_file "$src" "$dest" "$mode" "$own"
    done
    run systemctl daemon-reload
    echo "Units installed"
}

step_firewall_file() {
    say "Step 5: firewall rules (written now, loaded in step 10)"
    render_nft "$WORK/edr-hub.nft"
    put_file "$WORK/edr-hub.nft" "$ETC/edr-hub.nft" 0600 root:root
    nft -c -f "$ETC/edr-hub.nft"
    echo "Wrote $ETC/edr-hub.nft and checked it with nft -c -f; nothing is loaded yet"
    if [[ ${#FINAL_ADMIN[@]} -eq 0 ]]; then echo "WARNING: no admin address: SSH is open to everyone"; fi
    if [[ $JOINED_SSH -eq 1 ]]; then echo "The source of this ssh session, $SSH_SRC, was added to the admin list."; fi
}

step_updates() {
    say "Step 6: updates and reboots"
    if ! package_present unattended-upgrades; then
        record package unattended-upgrades
        # a new droplet's package lists can be empty or stale: refresh them first, and wait for a lock that
        # cloud-init or unattended-upgrades may hold
        run apt-get -o DPkg::Lock::Timeout=300 update -qq
        DEBIAN_FRONTEND=noninteractive run apt-get -o DPkg::Lock::Timeout=300 install -y -qq unattended-upgrades
    fi
    # the files of the kit are put in place by step 4; here only what apt says
    if ! apt-config dump 2>/dev/null | grep -q 'APT::Periodic::Unattended-Upgrade "1"'; then
        echo "NOTE: unattended upgrades are not switched on: run dpkg-reconfigure -plow unattended-upgrades"
    fi
    echo "Automatic reboot is off: reboot by hand when /var/run/reboot-required appears, and restart edr-hub after a python3 or openssl update"
    echo "Hub logs: journalctl --namespace edr-hub"
}

step_deadman() {
    say "Step 7: dead-man ping"
    echo "Optional. To switch it on: edr-hub settings set deadman_url -   (it tells a third party that a hub exists)"
}

step_backups() {
    say "Step 8: scheduled backups"
    echo "edr-hub-backup.timer runs daily at 02:15 UTC; it is enabled in step 9"
    if [[ $BACKUP_PASS_NEW -eq 1 ]]; then
        {
            echo
            echo "  BACKUP PASSPHRASE (shown once; store it off this machine): $BACKUP_PASS"
            echo "  It is in $ETC/backup.pass (root, 0600). An old backup needs the passphrase it was made with."
        } >&3
    else
        echo "$ETC/backup.pass exists and is kept (not shown again)"
    fi
    echo "Run once now:  sudo edr-hub ca-export   (the CA key leaves the hub only that way; keep the passphrase offline)"
    echo "Pull $BACKUPS to your own machine; no credentials go on the hub. Add a weekly DigitalOcean snapshot."
}

wait_health() {
    local _
    for _ in $(seq 1 45); do
        if "$CLI" health >/dev/null 2>&1; then return 0; fi
        sleep 2
    done
    return 1
}

rollback_code() {
    say "Rolling back the code"
    run systemctl stop edr-hub-ui.service edr-hub-out.service edr-hub.service || true
    if [[ -d $PREV ]]; then
        run rm -rf -- "${LIB:?}"
        run mv -- "$PREV" "$LIB"
        echo "The previous code is back in $LIB; the hub is left stopped."
    fi
    echo "Restore the data with the backup taken before the upgrade:"
    echo "    sudo edr-hub restore $BACKUPS/${BACKUP_FILE:-<the backup file>}"
    exit 4
}

step_start() {
    local u
    say "Step 9: start"
    for u in "${ENABLE_UNITS[@]}"; do
        record unit "$u"
    done
    run systemctl enable "${ENABLE_UNITS[@]}"
    run systemctl restart edr-hub.service
    if ! wait_health; then
        if [[ $MIGRATING -eq 1 ]]; then
            echo "The hub did not come up after the schema migration."
            rollback_code
        fi
        fatal "edr-hub did not become healthy: journalctl --namespace edr-hub -u edr-hub"
    fi
    run systemctl restart edr-hub-out.service edr-hub-ui.service
    run systemctl start edr-hub-backup.timer
    echo "edr-hub is healthy; edr-hub-out, edr-hub-ui and the backup timer are running"
}

step_firewall_load() {
    say "Step 10: apply the firewall, then confirm"
    run rm -f -- "$CONFIRM_MARK"
    nft -c -f "$ETC/edr-hub.nft"
    run nft -f "$ETC/edr-hub.nft"
    echo "Loaded table inet edr_hub"
    if [[ $OVER_SSH -eq 1 ]]; then
        run systemd-run --on-active=300 --unit=edr-hub-fw-rollback --description="Roll back the edr_hub firewall table unless install.sh --confirm runs" \
            /usr/sbin/nft delete table inet edr_hub
        echo
        echo "The firewall is loaded and will be removed again in 300 seconds unless you confirm."
        echo "From a NEW ssh session, run:   sudo $SRC/install.sh --confirm"
        for _ in $(seq 1 165); do
            if ! systemctl is-active --quiet edr-hub-fw-rollback.timer; then break; fi
            sleep 2
        done
        for _ in $(seq 1 8); do
            if [[ -e $CONFIRM_MARK ]]; then break; fi
            sleep 2
        done
        if [[ ! -e $CONFIRM_MARK ]]; then
            echo "The rollback timer fired: the table inet edr_hub is gone and the firewall is NOT in place." >&2
            echo "Nothing else is undone. Re-run install.sh and confirm in time (--confirm after this changes nothing)." >&2
            exit 4
        fi
        echo "Confirmed: the firewall stays, edr-hub-nft.service is enabled."
    else
        record unit edr-hub-nft.service
        run systemctl enable edr-hub-nft.service
        echo "No ssh session: no rollback timer. edr-hub-nft.service is enabled, so the table survives a reboot."
    fi
}

step_finish() {
    local rc=0
    say "Final checks"
    run bash "$LIB/check.sh" || rc=$?
    if [[ $rc -ge 2 ]]; then fatal "check.sh reported failures (exit $rc); fix them and run it again: $LIB/check.sh"; fi
    printf 'http://127.0.0.1:%s/\n' "$EFF_UI" | put_text "$ETC/ui-url" 0600 root:root
    cat <<EOF

Installed edr-hub ${NEW_VERSION:-}.
  CA SHA-256:      $CA_SHA
  Hub addresses:   ${FINAL_PUBLIC[*]}   ports $EFF_PORT (fleet) and $EFF_ENROLL (enrollment)
  Next:
    sudo edr-hub token create --name first      a one-time enrollment token for the first client
    sudo edr-hub alert test                     check that an alert reaches you
    sudo edr-hub ui-login                       a one-time dashboard URL (ssh -L $EFF_UI:127.0.0.1:$EFF_UI this-hub, then open it)
    sudo edr-hub ca-export                      once: the CA key, encrypted, for off-box storage
EOF
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^status: active'; then
        echo "  ufw is active; this installer did not touch it. Allow the hub ports yourself:"
        echo "    ufw allow $EFF_PORT/tcp"
        echo "    ufw allow $EFF_ENROLL/tcp"
    fi
}

# ---- --confirm: from a new ssh session, after step 10 -----------------------------------------------------------------
do_confirm() {
    if [[ $EUID -ne 0 ]]; then echo "ERROR: run as root (sudo $0 --confirm)" >&2; exit 3; fi
    if ! systemctl is-active --quiet edr-hub-fw-rollback.timer; then
        if [[ -e $CONFIRM_MARK ]]; then
            echo "Already confirmed: nothing to do."
            exit 0
        fi
        echo "No firewall change is waiting for confirmation: the rollback timer already fired, or no install is running." >&2
        echo "Nothing was changed. Re-run install.sh and confirm within 300 seconds." >&2
        exit 3
    fi
    run systemctl stop edr-hub-fw-rollback.timer
    manifest_add unit edr-hub-nft.service "$(prior_for unit edr-hub-nft.service)"
    run systemctl enable edr-hub-nft.service
    run install -m 0600 -o root -g root /dev/null "$CONFIRM_MARK"
    echo "Confirmed: the rollback timer is cancelled and edr-hub-nft.service is enabled, so the firewall survives a reboot."
}

# ---- main ---------------------------------------------------------------------------------------------------------------
main() {
    local answer

    parse_args "$@"

    if [[ $CONFIRM -eq 1 ]]; then
        do_confirm
        exit 0
    fi

    verify_tree
    if [[ ${#REFUSE[@]} -gt 0 && $PLAN -eq 0 ]]; then
        for answer in "${REFUSE[@]}"; do echo "REFUSED: $answer" >&2; done
        exit 3
    fi
    if [[ $PLAN -eq 0 && $EUID -ne 0 ]]; then
        echo "ERROR: run as root (sudo $0)" >&2
        exit 3
    fi
    compute_settings
    preflight

    if [[ $PLAN -eq 1 ]]; then
        plan
        exit $?
    fi

    # ---- nothing above this line changes anything -------------------------------------------------------------------
    if [[ ${#REFUSE[@]} -gt 0 ]]; then
        for answer in "${REFUSE[@]}"; do echo "REFUSED: $answer" >&2; done
        echo "Nothing was changed." >&2
        exit 3
    fi
    for answer in "${WARN[@]}"; do echo "WARNING: $answer"; done

    if [[ $YES -eq 0 ]]; then
        if [[ ! -t 0 ]]; then echo "No terminal to ask on; use --yes to go ahead (or --plan to see what would happen)." >&2; exit 3; fi
        read -rp "Install the EDR hub ${NEW_VERSION:-} on this machine (see --plan)? [y/N] " answer
        [[ $answer == y || $answer == Y ]] || { echo "Aborted"; exit 3; }
    fi

    if [[ $OVER_SSH -eq 1 && -z ${EDR_HUB_IN_UNIT:-} ]]; then
        echo "Over SSH: re-running under systemd-run --unit=edr-hub-install, so a dropped session does not stop the install half-way."
        echo "The output is also kept in $INSTALL_LOG (journalctl -u edr-hub-install shows it too)."
        exec systemd-run --unit=edr-hub-install --collect --wait --pipe --quiet --setenv=EDR_HUB_IN_UNIT=1 \
            --setenv="SSH_CONNECTION=$SSH_CONN" --setenv="SUDO_USER=${SUDO_USER:-}" \
            -- "$SRC/install.sh" "${ORIG_ARGS[@]}" --yes
    fi

    WORK=$(mktemp -d)
    trap cleanup EXIT
    trap 'on_error $? $LINENO' ERR
    exec 3>&1
    if [[ -n ${EDR_HUB_IN_UNIT:-} ]]; then
        run install -m 0600 -o root -g root /dev/null "$INSTALL_LOG"
        exec > >(tee -a --output-error=warn-nopipe "$INSTALL_LOG") 2>&1
        TEE_PID=$!
    fi

    if [[ $MIGRATING -eq 1 ]]; then migration_backup; fi
    step_users
    step_code
    step_init
    step_units
    step_firewall_file
    step_updates
    step_deadman
    step_backups
    step_start
    step_firewall_load
    step_finish

    if [[ -n $TEE_PID ]]; then
        exec >&- 2>&-
        wait "$TEE_PID" 2>/dev/null || true
    fi
    exit 0
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
