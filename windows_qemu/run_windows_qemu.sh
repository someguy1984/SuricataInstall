#!/usr/bin/env bash
# Boot the installed Windows (the whole physical NVMe disk) under QEMU/KVM, with OVMF + Secure Boot
# (Microsoft keys) and a software TPM 2.0. Nothing here touches the board's firmware or its NVRAM:
# UEFI variables live in a private OVMF vars file and the TPM is swtpm, both under ./state/.
#
#   sudo ./run_windows_qemu.sh                 # boot Windows, writes go to the real disk
#   sudo ./run_windows_qemu.sh --snapshot      # boot Windows, all disk writes discarded at exit
#   sudo ./run_windows_qemu.sh --help          # all options
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE_DIR=${STATE_DIR:-$SCRIPT_DIR/state}
# By serial, not /dev/nvmeXn1: the two NVMe drives swap names between boots on this machine.
DISK=${WIN_DISK:-/dev/disk/by-id/nvme-WD_BLACK_SN8100_2000GB_25264U801019}
MEM=16G
CPUS=8
SNAPSHOT=0
SECUREBOOT=1
TPM=1
NET=1
DISPLAY_KIND=gtk
USB_DEV=""
BOOT_USB=0
NO_REBOOT=0
RESET_VARS=0
DRY_RUN=0
FORCE=0
INSPECT=0
EXTRA=()

OVMF_DIR=/usr/share/OVMF
RUN_USER=${SUDO_USER:-j}

usage() {
  cat <<EOF
Usage: sudo $0 [options]

  --disk PATH        Windows disk (default: $DISK)
  --mem SIZE         guest RAM (default: $MEM)
  --cpus N           vCPUs (default: $CPUS)
  --snapshot         discard every write to the Windows disk when QEMU exits (overlay in state/)
  --no-secureboot    plain OVMF, no Secure Boot (uses a separate vars file)
  --no-tpm           no TPM (Windows 11 boots without one, but BitLocker/Hello will complain)
  --no-net           no network card
  --usb PATH         also attach a disk as a read-only USB stick (e.g. the Windows installer:
                     /dev/disk/by-id/usb-Fanxiang_F397_DD56419883BA4-0:0)
  --boot-usb         boot from the --usb stick first
  --display KIND     gtk (default) | sdl | vnc (127.0.0.1:5900) | none (use the monitor socket)
  --no-reboot        exit QEMU instead of rebooting the guest (catches a reset/bugcheck loop)
  --reset-vars       start again from a fresh copy of the OVMF vars (forgets boot entries)
  --inspect          plug in the INSPECT stick (guest/ inspection scripts) at boot; see inspect.sh
  --force            skip the "this looks like a Windows disk" check
  --dry-run          print the QEMU command and exit
  -- ARGS...         pass the rest straight to qemu-system-x86_64
EOF
}

die() { echo "error: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --disk) DISK=$2; shift ;;
    --mem) MEM=$2; shift ;;
    --cpus) CPUS=$2; shift ;;
    --snapshot) SNAPSHOT=1 ;;
    --no-secureboot) SECUREBOOT=0 ;;
    --no-tpm) TPM=0 ;;
    --no-net) NET=0 ;;
    --usb) USB_DEV=$2; shift ;;
    --boot-usb) BOOT_USB=1 ;;
    --display) DISPLAY_KIND=$2; shift ;;
    --no-reboot) NO_REBOOT=1 ;;
    --reset-vars) RESET_VARS=1 ;;
    --force) FORCE=1 ;;
    --inspect) INSPECT=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; EXTRA=("$@"); break ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
  shift
done

[ "$(id -u)" = 0 ] || [ "$DRY_RUN" = 1 ] || die "run with sudo (QEMU needs raw access to $DISK)"
command -v qemu-system-x86_64 >/dev/null || die "qemu-system-x86_64 not found (apt install qemu-system-x86)"
[ -e /dev/kvm ] || die "/dev/kvm missing (KVM not available)"
[ "$BOOT_USB" = 0 ] || [ -n "$USB_DEV" ] || die "--boot-usb needs --usb PATH"

# ---- safety checks on a raw block device ------------------------------------------------------
# Refuse a disk that Linux is using: a mounted partition, a dm/LUKS/LVM holder, or the disk
# holding / or /boot. Two writers on one NTFS volume is how C: got corrupted on 2026-10-09.
check_free_disk() {
  local path=$1 what=$2 dev name part
  [ -b "$path" ] || die "$what $path is not a block device"
  dev=$(readlink -f "$path")
  [ "$(lsblk -dno TYPE "$dev")" = disk ] || die "$what $dev is not a whole disk"
  name=$(basename "$dev")
  for part in "$dev" $(lsblk -nrpo NAME "$dev" | tail -n +2); do
    if [ -n "$(lsblk -nro MOUNTPOINTS "$part" | tr -d '[:space:]')" ]; then
      die "$what: $part is mounted ($(lsblk -nro MOUNTPOINTS "$part" | tr '\n' ' ')); unmount it first"
    fi
    if [ -n "$(ls -A "/sys/class/block/$(basename "$part")/holders" 2>/dev/null)" ]; then
      die "$what: $part is in use by device-mapper/LVM/RAID"
    fi
  done
  for mp in / /boot /boot/efi; do
    local src; src=$(findmnt -nvo SOURCE "$mp" 2>/dev/null) || continue
    if lsblk -nrso NAME "$src" 2>/dev/null | grep -qx "$name"; then
      die "$what $dev holds $mp of the running Linux; refusing"
    fi
  done
  echo "$dev"
}

WIN_DEV=$(check_free_disk "$DISK" "Windows disk")
if [ "$FORCE" = 0 ]; then
  types=$(lsblk -nro PARTTYPE "$WIN_DEV")
  grep -qi c12a7328-f81f-11d2-ba4b-00a0c93ec93b <<<"$types" || die "$WIN_DEV has no EFI System partition (--force to override)"
  grep -qi ebd0a0a2-b9e5-4433-87c0-68b6b72699c7 <<<"$types" || die "$WIN_DEV has no Microsoft basic data partition (--force to override)"
fi
USB_REAL=""
if [ -n "$USB_DEV" ]; then
  USB_REAL=$(check_free_disk "$USB_DEV" "USB stick")
  [ "$USB_REAL" != "$WIN_DEV" ] || die "--usb is the Windows disk"
fi

# ---- state: OVMF vars, TPM, snapshot overlay ---------------------------------------------------
mkdir -p "$STATE_DIR"
chown "$RUN_USER:$RUN_USER" "$STATE_DIR" 2>/dev/null || true
if [ "$SECUREBOOT" = 1 ]; then
  CODE=$OVMF_DIR/OVMF_CODE_4M.secboot.fd     # SMM build: Secure Boot variables are protected
  VARS_TEMPLATE=$OVMF_DIR/OVMF_VARS_4M.ms.fd # PK/KEK/db with Microsoft keys, incl. Windows UEFI CA 2023
  VARS=$STATE_DIR/OVMF_VARS.secboot.fd
else
  CODE=$OVMF_DIR/OVMF_CODE_4M.fd
  VARS_TEMPLATE=$OVMF_DIR/OVMF_VARS_4M.fd
  VARS=$STATE_DIR/OVMF_VARS.plain.fd
fi
[ -r "$CODE" ] && [ -r "$VARS_TEMPLATE" ] || die "OVMF firmware missing in $OVMF_DIR (apt install ovmf)"
if [ "$RESET_VARS" = 1 ] || [ ! -s "$VARS" ]; then
  if [ "$DRY_RUN" = 0 ]; then
    cp "$VARS_TEMPLATE" "$VARS"
    chown "$RUN_USER:$RUN_USER" "$VARS" 2>/dev/null || true
  fi
fi

if [ "$SNAPSHOT" = 1 ]; then
  export TMPDIR=$STATE_DIR   # QEMU puts the throwaway overlay here (deleted at exit); can grow by GBs
fi
SNAP_OPT=$([ "$SNAPSHOT" = 1 ] && echo ",snapshot=on" || true)

WIN_BOOTINDEX=1; USB_BOOTINDEX=2
[ "$BOOT_USB" = 1 ] && { WIN_BOOTINDEX=2; USB_BOOTINDEX=1; }

args=(
  -name windows-qemu
  -machine q35,smm=on,accel=kvm,vmport=off
  -global driver=cfi.pflash01,property=secure,value=on
  -global ICH9-LPC.disable_s3=1
  -drive if=pflash,format=raw,unit=0,file="$CODE",readonly=on
  -drive if=pflash,format=raw,unit=1,file="$VARS"
  -cpu host,topoext=on,hv_relaxed,hv_vapic,hv_spinlocks=0x1fff,hv_time,hv_vpindex,hv_synic,hv_stimer,hv_reset,hv_frequencies,hv_tlbflush,hv_ipi
  -smp "$CPUS",sockets=1,cores="$CPUS",threads=1
  -m "$MEM"
  -rtc base=localtime,clock=host,driftfix=slew
  -global kvm-pit.lost_tick_policy=discard
  # Windows was installed on NVMe, so it gets an NVMe controller: stornvme is boot-start, no
  # INACCESSIBLE_BOOT_DEVICE.
  -drive file="$WIN_DEV",if=none,id=windisk,format=raw,cache=none,aio=native,discard=unmap$SNAP_OPT
  -device nvme,drive=windisk,serial=WINQEMU0001,bootindex=$WIN_BOOTINDEX
  -device qemu-xhci,id=xhci
  -device usb-tablet,bus=xhci.0
  -vga std
  -monitor unix:"$STATE_DIR/monitor.sock",server=on,wait=off
)
if [ "$NET" = 1 ]; then
  args+=(-nic user,model=e1000e)   # Intel driver is in-box in Windows; NAT, no inbound ports
else
  args+=(-nic none)
fi
if [ -n "$USB_REAL" ]; then
  args+=(-drive file="$USB_REAL",if=none,id=usbstick,format=raw,readonly=on,cache=none
         -device usb-storage,bus=xhci.0,drive=usbstick,removable=on,bootindex=$USB_BOOTINDEX)
fi
[ "$NO_REBOOT" = 1 ] && args+=(-no-reboot)
if [ "$INSPECT" = 1 ]; then
  [ "$DRY_RUN" = 1 ] || STATE_DIR=$STATE_DIR "$SCRIPT_DIR/inspect.sh" prepare
  args+=(-drive file="$STATE_DIR/inspect.img",if=none,id=xfer,format=raw,cache=writethrough
         -device usb-storage,bus=xhci.0,drive=xfer,id=xferdev,removable=on)
fi
args+=("${EXTRA[@]}")

# ---- display -----------------------------------------------------------------------------------
# sudo drops the desktop's environment. Point GTK/SDL at the user's Wayland socket by absolute
# path, but keep root's own XDG_RUNTIME_DIR and an in-memory GSettings backend so a root GUI never
# writes root-owned files (dconf) into the user's /run/user/<uid>.
setup_gui_env() {
  local uid; uid=$(id -u "$RUN_USER")
  local udir=/run/user/$uid
  if [ -z "${WAYLAND_DISPLAY:-}" ] && [ -S "$udir/wayland-0" ]; then
    export WAYLAND_DISPLAY=$udir/wayland-0
  elif [ -n "${WAYLAND_DISPLAY:-}" ] && [ "${WAYLAND_DISPLAY#/}" = "$WAYLAND_DISPLAY" ]; then
    export WAYLAND_DISPLAY=$udir/$WAYLAND_DISPLAY
  fi
  if [ -z "${DISPLAY:-}" ]; then
    export DISPLAY=:0
    local xa; xa=$(ls "$udir"/.mutter-Xwaylandauth.* 2>/dev/null | head -1 || true)
    [ -n "$xa" ] && export XAUTHORITY=$xa
  fi
  export XDG_RUNTIME_DIR=/run/user/0
  [ -d "$XDG_RUNTIME_DIR" ] || { XDG_RUNTIME_DIR=$(mktemp -d); export XDG_RUNTIME_DIR; }
  export GSETTINGS_BACKEND=memory NO_AT_BRIDGE=1
}
case "$DISPLAY_KIND" in
  gtk) setup_gui_env; args+=(-display gtk,zoom-to-fit=on) ;;
  sdl) setup_gui_env; args+=(-display sdl) ;;
  vnc) args+=(-display none -vnc 127.0.0.1:0) ;;
  none) args+=(-display none) ;;
  *) die "unknown --display $DISPLAY_KIND" ;;
esac

if [ "$DRY_RUN" = 1 ]; then
  [ "$TPM" = 1 ] && args+=(-chardev socket,id=chrtpm,path="$STATE_DIR/tpm/swtpm.sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0)
  printf '%q ' qemu-system-x86_64 "${args[@]}"; echo
  exit 0
fi

# ---- TPM ---------------------------------------------------------------------------------------
TPM_PID=""
cleanup() {
  if [ -n "$TPM_PID" ]; then kill "$TPM_PID" 2>/dev/null || true; wait "$TPM_PID" 2>/dev/null || true; fi
  rm -f "$STATE_DIR/monitor.sock"
}
trap cleanup EXIT INT TERM

if [ "$TPM" = 1 ]; then
  command -v swtpm >/dev/null || die "swtpm not found (apt install swtpm), or use --no-tpm"
  # Persistent TPM state: Windows keeps its TPM-bound keys (Hello, BitLocker if ever enabled) here.
  # swtpm runs as the desktop user: Ubuntu's AppArmor profile only lets it write files that user owns.
  mkdir -p "$STATE_DIR/tpm"
  chown "$RUN_USER:$RUN_USER" "$STATE_DIR" "$STATE_DIR/tpm"
  rm -f "$STATE_DIR/tpm/swtpm.sock"
  runuser -u "$RUN_USER" -- swtpm socket --tpm2 --tpmstate dir="$STATE_DIR/tpm" \
    --ctrl type=unixio,path="$STATE_DIR/tpm/swtpm.sock" \
    --log level=1,file="$STATE_DIR/tpm/swtpm.log" >/dev/null 2>&1 &
  TPM_PID=$!
  for _ in $(seq 50); do [ -S "$STATE_DIR/tpm/swtpm.sock" ] && break; sleep 0.1; done
  [ -S "$STATE_DIR/tpm/swtpm.sock" ] || die "swtpm did not start (see $STATE_DIR/tpm/swtpm.log)"
  args+=(-chardev socket,id=chrtpm,path="$STATE_DIR/tpm/swtpm.sock"
         -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0)
fi

echo "Windows disk : $DISK -> $WIN_DEV$([ "$SNAPSHOT" = 1 ] && echo '  (snapshot: writes discarded)' || echo '  (READ-WRITE)')"
echo "Firmware     : $(basename "$CODE") + $VARS  (Secure Boot $([ "$SECUREBOOT" = 1 ] && echo on || echo off))"
echo "TPM          : $([ "$TPM" = 1 ] && echo "swtpm 2.0, state $STATE_DIR/tpm" || echo none)"
[ -n "$USB_REAL" ] && echo "USB stick    : $USB_DEV -> $USB_REAL (read-only$([ "$BOOT_USB" = 1 ] && echo ', boots first'))"
[ "$DISPLAY_KIND" = vnc ] && echo "Display      : VNC on 127.0.0.1:5900"
echo "Monitor      : $SCRIPT_DIR/monitor.py 'info status'   (socket $STATE_DIR/monitor.sock)"
qemu-system-x86_64 "${args[@]}"
