#!/usr/bin/env bash
# Host side of the Windows inspection. The guest scripts in guest/ travel on a small FAT32 disk
# ("INSPECT") that is hot-plugged into the running VM as a USB stick: no agent in Windows, no network.
#
#   sudo ./inspect.sh attach       write guest/ onto the INSPECT disk and plug it into the running VM
#   sudo ./inspect.sh collect      unplug it and copy its reports to ./reports/
#   sudo ./inspect.sh screenshot   save the VM screen to ./reports/screens/<time>.png
#   sudo ./inspect.sh status
#   sudo ./inspect.sh prepare      (used by run_windows_qemu.sh --inspect) refresh the disk without plugging it in
#
# WIPE=1 recreates the disk (drops reports not collected yet).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR=${STATE_DIR:-$SCRIPT_DIR/state}
IMG=$STATE_DIR/inspect.img
MON=$STATE_DIR/monitor.sock
REPORTS=$SCRIPT_DIR/reports
GUEST=$SCRIPT_DIR/guest
RUN_USER=${SUDO_USER:-j}

die() { echo "error: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run with sudo"

mon() { MONITOR_SOCK=$MON python3 "$SCRIPT_DIR/monitor.py" "$@"; }
vm_up() { [ -S "$MON" ] && mon 'info status' 2>/dev/null | grep -q 'VM status'; }
attached() { vm_up && mon 'info block' | grep -q '^xfer '; }

LOOP="" MNT=""
release() {
  if [ -n "$MNT" ]; then umount "$MNT" 2>/dev/null || true; rmdir "$MNT" 2>/dev/null || true; MNT=""; fi
  if [ -n "$LOOP" ]; then losetup -d "$LOOP" 2>/dev/null || true; LOOP=""; fi
}
trap release EXIT INT TERM

open_img() {  # $1 = ro|rw
  local ro=(); [ "$1" = ro ] && ro=(-r)
  LOOP=$(losetup "${ro[@]}" --find --show --partscan "$IMG")
  udevadm settle 2>/dev/null || true
  [ -b "${LOOP}p1" ] || die "no partition on $IMG"
  MNT=$(mktemp -d)
  mount -o "$1" "${LOOP}p1" "$MNT"
}

prepare() {
  attached && die "the INSPECT disk is plugged into the VM: run '$0 collect' first"
  mkdir -p "$STATE_DIR"
  if [ ! -s "$IMG" ] || [ "${WIPE:-0}" = 1 ]; then
    rm -f "$IMG"
    truncate -s 1G "$IMG"
    printf 'label: dos\nstart=2048, type=c\n' | sfdisk -q "$IMG"
    LOOP=$(losetup --find --show --partscan "$IMG"); udevadm settle 2>/dev/null || true
    mkfs.vfat -F 32 -n INSPECT "${LOOP}p1" >/dev/null
    losetup -d "$LOOP"; LOOP=""
    echo "created $IMG (1 GiB FAT32, label INSPECT)"
  fi
  open_img rw
  local f
  for f in "$GUEST"/*; do  # Windows wants CRLF in .cmd files; harmless for the rest
    sed -e 's/\r$//' -e 's/$/\r/' "$f" > "$MNT/$(basename "$f")"
  done
  mkdir -p "$MNT/reports"
  sync; release
}

attach() {
  vm_up || die "no running VM at $MON (start it with ./run_windows_qemu.sh, or pass it --inspect)"
  prepare
  local out
  out=$(mon "drive_add 0 if=none,id=xfer,file=$IMG,format=raw,cache=writethrough")
  out+=$(mon "device_add usb-storage,bus=xhci.0,drive=xfer,id=xferdev,removable=on")
  attached || die "hot-plug failed: $out"
  echo "INSPECT stick plugged into the VM."
  echo "In Windows: open the INSPECT drive, double-click RUN-INSPECTION.cmd (or RUN-FULL-INSPECTION.cmd),"
  echo "wait for 'Finished', then: sudo $0 collect"
}

collect() {
  if attached; then
    mon 'device_del xferdev' >/dev/null
    local i
    for i in $(seq 50); do attached || break; sleep 0.2; done
    attached && die "the VM did not release the INSPECT stick"
    echo "INSPECT stick unplugged from the VM."
  fi
  [ -s "$IMG" ] || die "no $IMG yet (run '$0 attach')"
  open_img ro
  mkdir -p "$REPORTS"
  local d n=0 newest=""
  for d in "$MNT"/reports/*/; do
    [ -d "$d" ] || continue
    cp -rn "$d" "$REPORTS/"
    n=$((n + 1)); newest=$REPORTS/$(basename "$d")
    [ -e "$d/DONE" ] || echo "warning: $(basename "$d") has no DONE marker (run interrupted, or collected too early)"
  done
  release
  chown -R "$RUN_USER:$RUN_USER" "$REPORTS"
  [ "$n" -gt 0 ] || { echo "no reports on the INSPECT disk yet"; return; }
  newest=$(ls -td "$REPORTS"/*/ | grep -v '/screens/$' | head -1)
  echo "copied $n report(s) to $REPORTS; newest: $newest"
  echo
  [ -f "$newest/summary.txt" ] && sed 's/^\xEF\xBB\xBF//; s/\r$//' "$newest/summary.txt"
}

screenshot() {
  vm_up || die "no running VM"
  mkdir -p "$REPORTS/screens"
  local base; base=$REPORTS/screens/$(date +%Y%m%d-%H%M%S)
  mon "screendump $base.ppm" >/dev/null
  python3 -I - "$base.ppm" <<'EOF'
import struct, sys, zlib
p = sys.argv[1]; d = open(p, 'rb').read(); fields = []; i = 0
while len(fields) < 4:
    while d[i:i+1].isspace(): i += 1
    j = i
    while not d[j:j+1].isspace(): j += 1
    fields.append(d[i:j]); i = j
w, h = int(fields[1]), int(fields[2]); px = d[i+1:]
raw = b''.join(b'\0' + px[y*w*3:(y+1)*w*3] for y in range(h))
chunk = lambda t, b: struct.pack('>I', len(b)) + t + b + struct.pack('>I', zlib.crc32(t + b) & 0xffffffff)
open(p[:-4] + '.png', 'wb').write(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
                                  + chunk(b'IDAT', zlib.compress(raw, 6)) + chunk(b'IEND', b''))
EOF
  rm -f "$base.ppm"; chown -R "$RUN_USER:$RUN_USER" "$REPORTS"
  echo "$base.png"
}

status() {
  if vm_up; then echo "VM: $(mon 'info status')"; else echo "VM: not running"; fi
  if attached; then echo "INSPECT stick: plugged in"; else echo "INSPECT stick: not plugged in"; fi
  [ -s "$IMG" ] && echo "disk image: $IMG" || echo "disk image: not created yet"
}

case "${1:-}" in
  attach) attach ;;
  collect) collect ;;
  screenshot) screenshot ;;
  status) status ;;
  prepare) prepare ;;
  *) sed -n '2,12p' "$0"; exit 1 ;;
esac
