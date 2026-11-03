#!/usr/bin/env bash
# Boot the installed Windows on the SENTINEL MM firmware (rev97 sources, QEMU build) instead of stock OVMF, to try to
# reproduce the board's "Windows resets a few seconds into the kernel" (CF9 0xE) and catch what does it: which SW SMI
# (value written to 0xB2) was raised from where, how long each vCPU sat in SMM, who wrote the reset, and the Windows
# stop code if it is a bugcheck. Companion of run_windows_qemu.sh (stock OVMF, where Windows boots fine).
#
#   sudo ./run_windows_sentinel_replica.sh                 # enrol keys if needed, boot Windows, capture, summarise
#   sudo ./run_windows_sentinel_replica.sh --usb /dev/disk/by-id/usb-... --boot-usb --no-disk   # installer stick only
#   sudo ./run_windows_sentinel_replica.sh --help
#
# The Windows disk is NEVER written: QEMU runs on a qcow2 overlay whose backing file (the raw disk) is opened
# read-only, and the overlay is deleted afterwards (--keep-overlay keeps it). Board firmware/NVRAM are not touched.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SENTINEL=${SENTINEL:-/home/j/sentinel-uefi}
FW=${FW:-$SENTINEL/firmware/qemu/sentinel-mm-winreplica}
KEYS=${KEYS:-$SENTINEL/efivars/rev_97}             # PK.esl KEK.esl db.esl dbx.esl = the live board store
PK_KEY=$SENTINEL/secureboot_keys/PK.key  PK_CRT=$SENTINEL/secureboot_keys/PK.crt
KEK_KEY=$SENTINEL/keys/KEK.key           KEK_CRT=$SENTINEL/keys/KEK.crt
DISK=${WIN_DISK:-/dev/disk/by-id/nvme-WD_BLACK_SN8100_2000GB_25264U801019}
OUT=${OUT:-$SENTINEL/smm_research/studies/$(date +%F)-windows-sentinel-replica}
MEM=16G; CPUS=8; ACCEL=kvm; TIMEOUT_MIN=20; DISPLAY_KIND=gtk; HOLD=0; NET=0; TPM=1; USE_DISK=1
USB_DEV=""; BOOT_USB=0; RE_ENROL=0; BUILD=0; DRY_RUN=0; KEEP_OVERLAY=0; TRACE_KB=16384; FORCE=0; EXTRA=()
RUN_USER=${SUDO_USER:-j}
[ "$RUN_USER" = root ] && RUN_USER=j

usage() {
  cat <<EOF
Usage: sudo $0 [options]

  --disk PATH       Windows disk (default: $DISK); always behind a throwaway overlay, never written
  --no-disk         no Windows disk (e.g. boot only the --usb installer stick)
  --usb PATH        attach a stick read-only as USB storage (e.g. the Windows installer)
  --boot-usb        boot the --usb stick first
  --cpus N          vCPUs (default $CPUS)        --mem SIZE   guest RAM (default $MEM)
  --accel kvm|tcg   kvm (default): KVM tracepoints + Hyper-V crash MSRs (stop code). tcg: -cpu EPYC, slow,
                    no KVM trace (SW SMIs come from QEMU's apm_io_write trace in qemu.log instead)
  --timeout MIN     stop and snapshot if nothing happens for MIN minutes (default $TIMEOUT_MIN)
  --hold            leave the VM paused at the event instead of quitting (inspect via the QMP socket)
  --display KIND    gtk (default) | sdl | vnc (127.0.0.1:5901) | none
  --net             user-mode NAT network (default: no network)
  --no-tpm          no TPM (default: a fresh swtpm 2.0 CRB per run)
  --re-enrol        redo the Secure Boot enrolment (vars-enrolled.fd) from --keys
  --keys DIR        PK/KEK/db/dbx .esl to enrol (default $KEYS)
  --build           (re)build the replica firmware from $SENTINEL/edk2 first (as $RUN_USER)
  --out DIR         results parent dir (default $OUT)
  --trace-kb N      ftrace buffer per host CPU in KiB (default $TRACE_KB)
  --keep-overlay    keep the qcow2 overlay (Windows' writes) in the run dir
  --force           skip the "this looks like a Windows disk" check
  --dry-run         print the QEMU command and exit
  -- ARGS...        extra qemu-system-x86_64 arguments

What it cannot reproduce: anything that needs the board itself. QEMU has its own ACPI tables (no ASUS/AMD AML, so
no ASUS WMI or AMD SW SMIs), no AMI DXE/AGESA, no PSP/ROM Armor, a q35 SMI path and qemu-xhci. Windows also loads
QEMU drivers, not the board's. A clean boot here points at the board-only part; a reset here is reproducible
with full visibility.
EOF
}
die() { echo "error: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --disk) DISK=$2; shift ;;
    --no-disk) USE_DISK=0 ;;
    --usb) USB_DEV=$2; shift ;;
    --boot-usb) BOOT_USB=1 ;;
    --cpus) CPUS=$2; shift ;;
    --mem) MEM=$2; shift ;;
    --accel) ACCEL=$2; shift ;;
    --timeout) TIMEOUT_MIN=$2; shift ;;
    --hold) HOLD=1 ;;
    --display) DISPLAY_KIND=$2; shift ;;
    --net) NET=1 ;;
    --no-tpm) TPM=0 ;;
    --re-enrol|--re-enroll) RE_ENROL=1 ;;
    --keys) KEYS=$2; shift ;;
    --build) BUILD=1 ;;
    --out) OUT=$2; shift ;;
    --trace-kb) TRACE_KB=$2; shift ;;
    --keep-overlay) KEEP_OVERLAY=1 ;;
    --force) FORCE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; EXTRA=("$@"); break ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
  shift
done

[ "$(id -u)" = 0 ] || [ "$DRY_RUN" = 1 ] || die "run with sudo (raw disk, KVM tracing)"
case "$ACCEL" in kvm) [ -e /dev/kvm ] || die "/dev/kvm missing" ;; tcg) ;; *) die "--accel kvm|tcg" ;; esac
[ "$BOOT_USB" = 0 ] || [ -n "$USB_DEV" ] || die "--boot-usb needs --usb PATH"
[ "$USE_DISK" = 1 ] || [ -n "$USB_DEV" ] || die "--no-disk without --usb leaves nothing to boot"
for t in qemu-system-x86_64 qemu-img python3; do command -v $t >/dev/null || die "$t not found"; done

# ---- safety checks (same rules as run_windows_qemu.sh) ---------------------------------------------------------
check_free_disk() {
  local path=$1 what=$2 dev name part
  [ -b "$path" ] || die "$what $path is not a block device"
  dev=$(readlink -f "$path")
  [ "$(lsblk -dno TYPE "$dev")" = disk ] || die "$what $dev is not a whole disk"
  name=$(basename "$dev")
  for part in "$dev" $(lsblk -nrpo NAME "$dev" | tail -n +2); do
    [ -z "$(lsblk -nro MOUNTPOINTS "$part" | tr -d '[:space:]')" ] || die "$what: $part is mounted; unmount it first"
    [ -z "$(ls -A "/sys/class/block/$(basename "$part")/holders" 2>/dev/null)" ] || die "$what: $part is held by dm/LVM/RAID"
    if command -v fuser >/dev/null && fuser -s "$part" 2>/dev/null; then die "$what: $part is open by another process (another VM?)"; fi
  done
  for mp in / /boot /boot/efi; do
    local src; src=$(findmnt -nvo SOURCE "$mp" 2>/dev/null) || continue
    if lsblk -nrso NAME "$src" 2>/dev/null | grep -qx "$name"; then die "$what $dev holds $mp of the running Linux"; fi
  done
  echo "$dev"
}
WIN_DEV=""
if [ "$USE_DISK" = 1 ]; then
  WIN_DEV=$(check_free_disk "$DISK" "Windows disk")
  if [ "$FORCE" = 0 ]; then
    types=$(lsblk -nro PARTTYPE "$WIN_DEV")
    grep -qi c12a7328-f81f-11d2-ba4b-00a0c93ec93b <<<"$types" || die "$WIN_DEV has no EFI System partition"
    grep -qi ebd0a0a2-b9e5-4433-87c0-68b6b72699c7 <<<"$types" || die "$WIN_DEV has no Microsoft basic data partition"
  fi
fi
USB_REAL=""
[ -z "$USB_DEV" ] || USB_REAL=$(check_free_disk "$USB_DEV" "USB stick")
[ -z "$USB_REAL" ] || [ "$USB_REAL" != "$WIN_DEV" ] || die "--usb is the Windows disk"

# ---- firmware -------------------------------------------------------------------------------------------------
build_firmware() {
  echo "== building the replica firmware (as $RUN_USER) from $SENTINEL/edk2"
  mkdir -p "$FW"; chown "$RUN_USER:$RUN_USER" "$FW"
  runuser -u "$RUN_USER" -- bash -c "cd '$SENTINEL/edk2' && export WORKSPACE=\$PWD EDK_TOOLS_PATH=\$PWD/BaseTools \
    && source edksetup.sh BaseTools >/dev/null && python3 SentinelMmPkg/Cpu/derive_cpu.py >/dev/null \
    && python3 SentinelMmPkg/Platform/Ovmf/derive_platform.py >/dev/null \
    && build -p SentinelMmPkg/Platform/Ovmf/SentinelOvmfIa32X64.dsc -a IA32 -a X64 -t GCC -b DEBUG -n \$(nproc) \
       -D NETWORK_ENABLE=FALSE -D SECURE_BOOT_ENABLE=TRUE -D TPM2_ENABLE=TRUE \
       -D SENTINEL_TEST_MODULES=FALSE -D SENTINEL_KVM=TRUE \
       --pcd gSentinelMmPkgTokenSpaceGuid.PcdSentinelMmTestHooks=FALSE \
       --pcd gEfiMdeModulePkgTokenSpaceGuid.PcdResetOnMemoryTypeInformationChange=FALSE \
       --pcd 'gSentinelMmPkgTokenSpaceGuid.PcdSentinelRevision=Sentinel rev97-winreplica-kvm' > '$FW/build.log' 2>&1" \
    || { tail -20 "$FW/build.log"; die "firmware build failed ($FW/build.log)"; }
  local b=$SENTINEL/edk2/Build/SentinelOvmf3264/DEBUG_GCC
  cp "$b/FV/OVMF_CODE.fd" "$b/FV/OVMF_VARS.fd" "$b/X64/Shell.efi" "$FW/"
  (cd "$FW" && sha256sum OVMF_CODE.fd OVMF_VARS.fd Shell.efi > SHA256SUMS)
  rm -f "$FW/vars-enrolled.fd"                      # a new firmware gets a fresh enrolment
  chown -R "$RUN_USER:$RUN_USER" "$FW"
}
[ "$BUILD" = 1 ] && [ "$DRY_RUN" = 0 ] && build_firmware
for f in OVMF_CODE.fd OVMF_VARS.fd Shell.efi; do [ -s "$FW/$f" ] || die "$FW/$f missing: run with --build"; done
FW_SHA=$(sha256sum "$FW/OVMF_CODE.fd" | cut -c1-64)

# ---- one-time Secure Boot enrolment: the board's live PK/KEK/db/dbx into a Setup Mode varstore -----------------
# OVMF leaves the shell out of Secure Boot builds, so the gate build's Shell.efi boots from a small FAT disk as
# \EFI\BOOT\BOOTX64.EFI (Setup Mode: nothing is verified yet) and startup.nsh runs `dmpstore -all -l`.
enrol() {
  echo "== enrolling Secure Boot keys from $KEYS"
  for f in PK KEK db dbx; do [ -s "$KEYS/$f.esl" ] || die "$KEYS/$f.esl missing"; done
  local e=$FW/enrol; rm -rf "$e"; mkdir -p "$e/fat/EFI/BOOT"
  python3 -I "$SCRIPT_DIR/replica/make_key_dmpstore.py" "$KEYS" "$PK_KEY" "$PK_CRT" "$KEK_KEY" "$KEK_CRT" "$e/auth"
  cp "$FW/Shell.efi" "$e/fat/EFI/BOOT/BOOTX64.EFI"; cp "$e/auth/sentinel-keys.dmp" "$e/fat/"
  printf '%s\r\n' '@echo -off' 'for %m in fs0 fs1 fs2 fs3 fs4' '  if exist %m:\sentinel-keys.dmp then' '    %m:' \
    '  endif' 'endfor' 'echo SENTINEL-ENROL-BEGIN' 'dmpstore -all -l sentinel-keys.dmp' 'echo SENTINEL-ENROL-AFTER' \
    'dmpstore SetupMode' 'dmpstore SecureBoot' 'dmpstore -all PK' 'dmpstore -all KEK' \
    'dmpstore db -guid d719b2cb-3d3a-4596-a3bc-dad00e67656f' 'dmpstore dbx -guid d719b2cb-3d3a-4596-a3bc-dad00e67656f' \
    'echo SENTINEL-ENROL-END' 'reset -s' > "$e/fat/startup.nsh"
  cp "$FW/OVMF_VARS.fd" "$e/vars.fd"
  timeout 300 qemu-system-x86_64 -machine q35,smm=on,accel=kvm -cpu host -smp 2 -m 2048 \
    -global driver=cfi.pflash01,property=secure,value=on -global ICH9-LPC.disable_s3=1 \
    -drive if=pflash,format=raw,unit=0,file="$FW/OVMF_CODE.fd",readonly=on \
    -drive if=pflash,format=raw,unit=1,file="$e/vars.fd" \
    -drive file=fat:"$e/fat",format=raw,if=none,id=keys,readonly=on -device virtio-blk-pci,drive=keys \
    -nographic -monitor none -net none -debugcon file:"$e/debug.log" -global isa-debugcon.iobase=0x402 \
    -serial file:"$e/serial.log" </dev/null >"$e/qemu.out" 2>&1 || die "enrolment boot did not shut down (see $e)"
  tr -d '\r' < "$e/serial.log" | sed 's/\x1b\[[0-9;]*[A-Za-z]//g' | awk '/SENTINEL-ENROL-BEGIN/{p=1} p' > "$e/enrol.txt"
  local ok=1
  grep -q "SetupMode' DataSize = 0x01" "$e/enrol.txt" && grep -A1 "SetupMode' DataSize" "$e/enrol.txt" | grep -q ': 00 ' || ok=0
  grep -A1 "SecureBoot' DataSize" "$e/enrol.txt" | grep -q ': 01 ' || ok=0
  for v in PK KEK; do grep -q "EFIGlobalVariable:$v' DataSize = 0x$(printf '%X' "$(stat -c%s "$KEYS/$v.esl")")" "$e/enrol.txt" || ok=0; done
  for v in db dbx; do grep -q ":$v' DataSize = 0x$(printf '%X' "$(stat -c%s "$KEYS/$v.esl")")" "$e/enrol.txt" || ok=0; done
  grep -qi 'fail' "$e/enrol.txt" && ok=0
  [ "$ok" = 1 ] || { cat "$e/enrol.txt"; die "enrolment check failed (see $e/enrol.txt)"; }
  cp "$e/vars.fd" "$FW/vars-enrolled.fd"
  chown -R "$RUN_USER:$RUN_USER" "$FW"
  echo "   enrolled: User Mode, SecureBoot 1, PK/KEK/db/dbx sizes = $KEYS (log $e/enrol.txt)"
}
if [ "$DRY_RUN" = 0 ] && { [ "$RE_ENROL" = 1 ] || [ ! -s "$FW/vars-enrolled.fd" ]; }; then enrol; fi

# ---- run directory ----------------------------------------------------------------------------------------------
RUN=$OUT/run-$(date +%Y%m%dT%H%M%S)
if [ "$DRY_RUN" = 0 ]; then
  mkdir -p "$RUN"; chown "$RUN_USER:$RUN_USER" "$OUT" "$RUN"
  cp "$FW/vars-enrolled.fd" "$RUN/vars-run.fd"
  if [ "$USE_DISK" = 1 ]; then
    qemu-img create -q -f qcow2 -b "$WIN_DEV" -F raw "$RUN/windisk-overlay.qcow2"
  fi
fi

args=(
  -name sentinel-winreplica
  -action reboot=shutdown,shutdown=pause,panic=pause
  -global driver=cfi.pflash01,property=secure,value=on
  -global ICH9-LPC.disable_s3=1
  -drive if=pflash,format=raw,unit=0,file="$FW/OVMF_CODE.fd",readonly=on
  -drive if=pflash,format=raw,unit=1,file="$RUN/vars-run.fd"
  -smp "$CPUS",sockets=1,cores="$CPUS",threads=1
  -m "$MEM"
  -rtc base=localtime,clock=host,driftfix=slew
  -device qemu-xhci,id=xhci
  -device usb-tablet,bus=xhci.0
  -vga std
  -debugcon file:"$RUN/firmware-debug.log" -global isa-debugcon.iobase=0x402
  -serial file:"$RUN/serial.log"
  -qmp unix:"$RUN/qmp.sock",server=on,wait=off
  -D "$RUN/qemu.log" -d guest_errors,unimp -trace apm_io_write
)
if [ "$ACCEL" = kvm ]; then
  args+=(-machine q35,smm=on,accel=kvm,vmport=off
         -cpu host,topoext=on,hv_relaxed,hv_vapic,hv_spinlocks=0x1fff,hv_time,hv_vpindex,hv_synic,hv_stimer,hv_reset,hv_frequencies,hv_tlbflush,hv_ipi,hv_crash
         -global kvm-pit.lost_tick_policy=discard)
else
  args+=(-machine q35,smm=on,vmport=off -accel tcg,thread=multi,tb-size=1024 -cpu EPYC)
fi
WIN_BOOTINDEX=1; USB_BOOTINDEX=2
[ "$BOOT_USB" = 1 ] && { WIN_BOOTINDEX=2; USB_BOOTINDEX=1; }
[ "$USE_DISK" = 1 ] && args+=(-drive file="$RUN/windisk-overlay.qcow2",if=none,id=windisk,format=qcow2,cache=writeback,discard=unmap
                             -device nvme,drive=windisk,serial=WINQEMU0001,bootindex=$WIN_BOOTINDEX)
[ -n "$USB_REAL" ] && args+=(-drive file="$USB_REAL",if=none,id=usbstick,format=raw,readonly=on,cache=none
                             -device usb-storage,bus=xhci.0,drive=usbstick,removable=on,bootindex=$USB_BOOTINDEX)
[ "$NET" = 1 ] && args+=(-nic user,model=e1000e) || args+=(-nic none)
args+=("${EXTRA[@]}")

setup_gui_env() {   # as run_windows_qemu.sh: the desktop user's Wayland/X socket, root's own runtime dir
  local uid; uid=$(id -u "$RUN_USER"); local udir=/run/user/$uid
  if [ -z "${WAYLAND_DISPLAY:-}" ] && [ -S "$udir/wayland-0" ]; then export WAYLAND_DISPLAY=$udir/wayland-0
  elif [ -n "${WAYLAND_DISPLAY:-}" ] && [ "${WAYLAND_DISPLAY#/}" = "$WAYLAND_DISPLAY" ]; then export WAYLAND_DISPLAY=$udir/$WAYLAND_DISPLAY; fi
  if [ -z "${DISPLAY:-}" ]; then
    export DISPLAY=:0
    local xa; xa=$(ls "$udir"/.mutter-Xwaylandauth.* 2>/dev/null | head -1 || true); [ -n "$xa" ] && export XAUTHORITY=$xa
  fi
  export XDG_RUNTIME_DIR=/run/user/0
  [ -d "$XDG_RUNTIME_DIR" ] || { XDG_RUNTIME_DIR=$(mktemp -d); export XDG_RUNTIME_DIR; }
  export GSETTINGS_BACKEND=memory NO_AT_BRIDGE=1
}
case "$DISPLAY_KIND" in
  gtk) setup_gui_env; args+=(-display gtk,zoom-to-fit=on) ;;
  sdl) setup_gui_env; args+=(-display sdl) ;;
  vnc) args+=(-display none -vnc 127.0.0.1:1) ;;
  none) args+=(-display none) ;;
  *) die "unknown --display $DISPLAY_KIND" ;;
esac

if [ "$DRY_RUN" = 1 ]; then printf '%q ' qemu-system-x86_64 "${args[@]}"; echo; exit 0; fi

# ---- TPM, KVM trace, cleanup ------------------------------------------------------------------------------------
TPM_PID=""; QEMU_PID=""; TI=""
finish() {
  [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null || true
  [ -n "$TPM_PID" ] && { kill "$TPM_PID" 2>/dev/null || true; wait "$TPM_PID" 2>/dev/null || true; }
  if [ -n "$TI" ] && [ -d "$TI" ]; then
    echo 0 > "$TI/tracing_on" 2>/dev/null || true
    cp "$TI/trace" "$RUN/kvm-trace.txt" 2>/dev/null || true
    for ev in kvm_smm_transition kvm_pio kvm_exit; do echo 0 > "$TI/events/kvm/$ev/enable" 2>/dev/null || true; done
    rmdir "$TI" 2>/dev/null || true
  fi
  rm -f "$RUN/qmp.sock"
  [ "$KEEP_OVERLAY" = 1 ] || rm -f "$RUN/windisk-overlay.qcow2"
  chown -R "$RUN_USER:$RUN_USER" "$RUN" 2>/dev/null || true
}
trap finish EXIT INT TERM

if [ "$TPM" = 1 ]; then
  command -v swtpm >/dev/null || die "swtpm not found, or use --no-tpm"
  mkdir -p "$RUN/tpm"; chown "$RUN_USER:$RUN_USER" "$RUN/tpm"
  runuser -u "$RUN_USER" -- swtpm socket --tpm2 --tpmstate dir="$RUN/tpm" --ctrl type=unixio,path="$RUN/tpm/sock" \
    --log level=1,file="$RUN/tpm/swtpm.log" >/dev/null 2>&1 &
  TPM_PID=$!
  for _ in $(seq 50); do [ -S "$RUN/tpm/sock" ] && break; sleep 0.1; done
  [ -S "$RUN/tpm/sock" ] || die "swtpm did not start"
  args+=(-chardev socket,id=chrtpm,path="$RUN/tpm/sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0)
fi

TRACE_ARG=()
if [ "$ACCEL" = kvm ]; then
  T=/sys/kernel/tracing; TI=$T/instances/sentinel_winreplica_$$
  mkdir "$TI"
  echo mono > "$TI/trace_clock"
  echo "$TRACE_KB" > "$TI/buffer_size_kb"
  echo 'port == 0xb2 || port == 0xb3 || port == 0xcf9 || port == 0x64' > "$TI/events/kvm/kvm_pio/filter"
  # SVM: exit 0x7b = IOIO (EXITINFO1[31:16] = port, bit 0 = IN), 0x7f = SHUTDOWN (triple fault)
  echo 'exit_reason == 0x7f || (exit_reason == 0x7b && ((info1 >= 0xb20000 && info1 < 0xb40000) || (info1 >= 0xcf90000 && info1 < 0xcfa0000) || (info1 >= 0x640000 && info1 < 0x650000)))' \
    > "$TI/events/kvm/kvm_exit/filter"
  for ev in kvm_smm_transition kvm_pio kvm_exit; do echo 1 > "$TI/events/kvm/$ev/enable"; done
  echo 1 > "$TI/tracing_on"
  TRACE_ARG=(--trace-instance "$TI")
fi

GITREV=$(git -c safe.directory="$SENTINEL" -C "$SENTINEL" rev-parse --short HEAD 2>/dev/null || echo '?')
python3 - "$RUN/run.json" <<EOF
import json, sys, time
json.dump({"started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "firmware": "$FW/OVMF_CODE.fd", "firmware_sha256": "$FW_SHA",
           "sentinel_git": "$GITREV", "accel": "$ACCEL", "cpus": "$CPUS", "mem": "$MEM", "keys": "$KEYS",
           "disk": "$DISK -> $WIN_DEV (qcow2 overlay, base read-only)" if "$USE_DISK" == "1" else None,
           "usb": "$USB_DEV" or None, "boot_usb": "$BOOT_USB" == "1", "timeout_min": $TIMEOUT_MIN,
           "qemu_args": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "${args[@]}")},
          open(sys.argv[1], "w"), indent=1)
EOF

echo "Run dir      : $RUN"
echo "Firmware     : Sentinel MM replica ${FW_SHA:0:16}… (rev97 sources $GITREV), Secure Boot ON with $KEYS"
[ "$USE_DISK" = 1 ] && echo "Windows disk : $WIN_DEV via $RUN/windisk-overlay.qcow2 (base read-only, overlay discarded)"
[ -n "$USB_REAL" ] && echo "USB stick    : $USB_REAL (read-only$([ "$BOOT_USB" = 1 ] && echo ', boots first'))"
echo "Capture      : $([ "$ACCEL" = kvm ] && echo "KVM trace (SMM transitions, 0xB2/0xCF9/0x64 writes), hv-crash stop code, " )firmware debug log, screens"
echo "Stops on     : guest reset / bugcheck / shutdown, or after $TIMEOUT_MIN min$([ "$HOLD" = 1 ] && echo ' (then stays paused: --hold)')"

qemu-system-x86_64 "${args[@]}" &
QEMU_PID=$!
WATCH=(python3 -I "$SCRIPT_DIR/replica/qmp_watch.py" "$RUN" "$RUN/qmp.sock" --timeout $((TIMEOUT_MIN * 60)) --cpus "$CPUS" "${TRACE_ARG[@]}")
[ "$HOLD" = 1 ] && WATCH+=(--hold)
"${WATCH[@]}" || echo "qmp_watch exited with $?"
wait "$QEMU_PID" 2>/dev/null || true
QEMU_PID=""
finish; trap - EXIT INT TERM
python3 -I "$SCRIPT_DIR/replica/analyze_run.py" "$RUN" --sentinel "$SENTINEL" || true
chown -R "$RUN_USER:$RUN_USER" "$RUN" 2>/dev/null || true
echo "Summary: $RUN/SUMMARY.md"
