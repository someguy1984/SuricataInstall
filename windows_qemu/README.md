# Windows under QEMU/KVM

Boots the installed Windows straight off its physical NVMe disk (WD_BLACK SN8100, picked by serial
under `/dev/disk/by-id/`, never by `nvmeXn1`, which swaps between boots) inside a VM. Useful when the
board firmware can't boot Windows: it tells you whether Windows itself is healthy, and lets you get into it.

    sudo ./run_windows_qemu.sh               # normal boot, writes go to the real disk
    sudo ./run_windows_qemu.sh --snapshot    # test boot, every disk write thrown away at exit
    sudo ./run_windows_qemu.sh --usb /dev/disk/by-id/usb-Fanxiang_F397_DD56419883BA4-0:0 --boot-usb
                                             # boot the installer stick (read-only) with the disk attached
    sudo ./run_windows_qemu.sh --help

## What the VM is

- q35 + KVM, `-cpu host` with Hyper-V enlightenments, 8 vCPUs / 8 GiB by default.
- Ubuntu's OVMF Secure Boot build with the Microsoft key set (includes *Windows UEFI CA 2023*,
  which signs this disk's `bootmgfw.efi`). `--no-secureboot` for plain OVMF.
- swtpm TPM 2.0 (CRB), state kept in `state/tpm/` so Windows sees the same TPM every run.
- Windows disk on an emulated **NVMe** controller (Windows was installed on NVMe, so `stornvme` is
  already boot-start), e1000e NIC on user-mode NAT, USB tablet, `std` VGA.
- Monitor socket: `sudo ./monitor.py` e.g. `sudo ./monitor.py "info status" "screendump /tmp/x.ppm"`.

## What it does not touch

The board's SPI flash, its NVRAM and its Secure Boot key store. UEFI variables written by Windows in
the VM go to `state/OVMF_VARS.*.fd` and the TPM is software. The only shared thing is the disk.

## Safety checks (the script refuses to start if…)

- any partition of the Windows disk (or `--usb` stick) is mounted or held by dm/LVM, or the disk holds
  `/`, `/boot` or `/boot/efi`. Never boot the VM while Linux has the NTFS volume mounted.
- the disk has no EFI System + Microsoft basic data partition (`--force` to override).

## Notes

- The first boot on "new hardware" takes a while (driver install). Booting back on bare metal is fine.
- Windows activation may show as not activated inside the VM; that doesn't affect bare metal.
- Without `--snapshot`, anything Windows writes (updates, chkdsk) is real. With `--snapshot` the overlay
  lives in `state/` while QEMU runs and can grow by several GB.
- If the GTK window doesn't open from `sudo`, try `--display sdl` or `--display vnc`
  (then connect a VNC viewer to `127.0.0.1:5900`).
- `--no-reboot` makes QEMU exit instead of rebooting the guest, to catch a reset loop.

## Inspecting Windows from the host (`inspect.sh`)

`guest/` holds a read-only PowerShell inspection (`Inspect-Windows.ps1`). It travels on a 1 GiB FAT32
disk labelled INSPECT (`state/inspect.img`) that is hot-plugged into the running VM as a USB stick:
no agent in Windows, no network.

    sudo ./inspect.sh attach       # plug the stick into the running VM (or start the VM with --inspect)
    # in Windows: INSPECT drive -> RUN-INSPECTION.cmd (2-5 min) or RUN-FULL-INSPECTION.cmd (+ sfc/DISM/chkdsk, 20-40 min)
    sudo ./inspect.sh collect      # unplug it, copy reports to ./reports/<COMPUTER>-<time>/, print summary.txt
    sudo ./inspect.sh screenshot   # VM screen -> ./reports/screens/<time>.png

What it checks: Secure Boot, TPM, VBS, BitLocker; BCD overrides (testsigning, nointegritychecks,
debug); Authenticode of every ESP file plus winload, ntoskrnl, hal, ci and bootmgfw (the ESP copy against
the C:\Windows\Boot copies); every driver and service binary; 30 days of Kernel-Power 41, BugCheck,
WHEA, NTFS, disk and Code Integrity events; crash dumps (bugcheck code read from the dump header);
SrtTrail, bootstat and measured-boot TCG logs; Fast Startup and the dirty bit; WPBT (`wpbbin.exe`) and
ASUS software; Run keys, Winlogon, AppInit, IFEO, scheduled tasks, WMI subscriptions, hosts file, root
CAs; and Defender status, exclusions and detections.

## Network

`-nic user` (the default) is QEMU's user-mode NAT. Windows' connections are opened by the QEMU process
on the host, so they leave through the host stack: UFW, then Suricata inline (the mangle OUTPUT
NFQUEUE). Nothing can connect in. Known gaps: the guest's 10.0.2.2 is the host's 127.0.0.1, and `-o lo`
is accepted before NFQUEUE, so that path is not inspected. The guest can also reach the LAN
(192.168.0.0/24). `--no-net` turns networking off.
