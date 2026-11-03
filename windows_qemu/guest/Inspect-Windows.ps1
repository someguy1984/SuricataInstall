<#
  Inspect-Windows.ps1 - read-only health, integrity and tamper inspection of this Windows install.

  Run it through RUN-INSPECTION.cmd (asks for admin). RUN-FULL-INSPECTION.cmd adds -Full:
  sfc /verifyonly, DISM /ScanHealth and an online chkdsk scan (20-40 minutes).

  Everything goes to <this drive>\reports\<COMPUTER>-<timestamp>\. Nothing on C: is changed, apart
  from the logs Windows itself writes while sfc/DISM run. Nothing is sent anywhere.
  ASCII only on purpose: Windows PowerShell 5.1 reads BOM-less scripts as ANSI.
#>
param([switch]$Full)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Not elevated: run RUN-INSPECTION.cmd (it asks for admin).' -ForegroundColor Red
    exit 1
}

$XferRoot = Split-Path -Qualifier $PSCommandPath
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Out = Join-Path $XferRoot ('reports\{0}-{1}' -f $env:COMPUTERNAME, $Stamp)
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Summary = New-Object System.Collections.Generic.List[string]
$Colors = @{ OK = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Gray' }
$script:SigRows = New-Object System.Collections.Generic.List[object]
$Since = (Get-Date).AddDays(-30)

function P([string]$Name) { Join-Path $Out $Name }

function Note([string]$Level, [string]$Msg) {
    $line = '[{0}] {1}' -f $Level, $Msg
    $Summary.Add($line)
    Write-Host $line -ForegroundColor $Colors[$Level]
}

function Save([object]$Data, [string]$Name) {
    $Data | Out-File -Encoding utf8 -Width 400 -FilePath (P $Name)
}

function Section([string]$Name, [scriptblock]$Body) {
    Write-Host ''
    Write-Host ('== ' + $Name) -ForegroundColor Cyan
    $t0 = Get-Date
    try { & $Body }
    catch {
        Note 'WARN' ('{0}: section failed: {1}' -f $Name, $_.Exception.Message)
        ('[{0}] {1}' -f $Name, ($_ | Out-String)) | Out-File -Append -Encoding utf8 -FilePath (P 'errors.txt')
    }
    ('{0}: {1:N0} s' -f $Name, ((Get-Date) - $t0).TotalSeconds) | Out-File -Append -Encoding utf8 -FilePath (P 'timing.txt')
}

function Get-SigRow([string]$Path, [string]$Kind) {
    $hash = $null; $sig = $null
    try { $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash } catch { }
    try { $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop } catch { }
    $status = 'Unchecked'; $signer = ''; $issuer = ''
    if ($sig) {
        $status = [string]$sig.Status
        if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject; $issuer = $sig.SignerCertificate.Issuer }
    }
    $fi = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    $row = [pscustomobject]@{
        Kind     = $Kind
        Path     = $Path
        Status   = $status
        Signer   = $signer
        Issuer   = $issuer
        Version  = $(if ($fi) { $fi.VersionInfo.FileVersion } else { '' })
        Size     = $(if ($fi) { $fi.Length } else { '' })
        Modified = $(if ($fi) { $fi.LastWriteTimeUtc.ToString('u') } else { '' })
        SHA256   = $hash
    }
    $script:SigRows.Add($row)
    $row
}

function Test-Microsoft([string]$Signer) { $Signer -match 'O=Microsoft Corporation' }

function Get-EvData($Event) {
    try {
        $x = [xml]$Event.ToXml()
        (@($x.Event.EventData.Data) | Where-Object { $_ } | ForEach-Object {
            if ($_ -is [string]) { $_ } else { '{0}={1}' -f $_.Name, $_.'#text' }
        }) -join '; '
    } catch { '' }
}

function Read-DumpHeader([string]$Path) {
    try {
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try { $b = New-Object byte[] 0x60; [void]$fs.Read($b, 0, 0x60) } finally { $fs.Close() }
        $magic = [Text.Encoding]::ASCII.GetString($b, 0, 8)
        if ($magic -eq 'PAGEDU64') {
            return ('bugcheck 0x{0:X8} (0x{1:X}, 0x{2:X}, 0x{3:X}, 0x{4:X})' -f [BitConverter]::ToUInt32($b, 0x38),
                [BitConverter]::ToUInt64($b, 0x40), [BitConverter]::ToUInt64($b, 0x48), [BitConverter]::ToUInt64($b, 0x50), [BitConverter]::ToUInt64($b, 0x58))
        }
        if ($magic.StartsWith('MDMP')) { return 'user-mode/triage minidump' }
        return ('unknown header "{0}"' -f ($magic -replace '[^\x20-\x7e]', '.'))
    } catch { return ('unreadable: {0}' -f $_.Exception.Message) }
}

Write-Host ('Windows inspection -> {0}{1}' -f $Out, $(if ($Full) { '  (FULL: sfc + DISM + chkdsk, 20-40 min)' } else { '' })) -ForegroundColor Cyan

# ------------------------------------------------------------------------------------------------
Section 'System' {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
    Note 'INFO' ('{0} {1}, build {2}.{3}, installed {4}, this boot {5}' -f $os.Caption, $os.OSArchitecture, $os.BuildNumber, $ubr, $os.InstallDate, $os.LastBootUpTime)
    Note 'INFO' ('Running on {0} {1}, firmware {2} {3} (in QEMU this is OVMF, not the board)' -f $cs.Manufacturer, $cs.Model, $bios.Manufacturer, $bios.SMBIOSBIOSVersion)
    Save ($os, $cs, $bios | Format-List * | Out-String) 'system.txt'
    Save (Get-HotFix | Sort-Object InstalledOn | Format-Table -AutoSize | Out-String -Width 300) 'hotfixes.txt'
}

Section 'Secure Boot, TPM, VBS, BitLocker' {
    $sb = $null
    try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop } catch { }
    if ($sb -eq $true) { Note 'OK' 'Secure Boot on (in QEMU: the VM OVMF keys, not the board key store)' }
    elseif ($sb -eq $false) { Note 'WARN' 'Secure Boot off' }
    else { Note 'INFO' 'Secure Boot state not readable' }

    $tpm = Get-Tpm
    Save ($tpm | Format-List * | Out-String) 'tpm.txt'
    if ($tpm.TpmPresent -and $tpm.TpmReady) { Note 'OK' 'TPM present and ready' } else { Note 'WARN' ('TPM present={0} ready={1}' -f $tpm.TpmPresent, $tpm.TpmReady) }

    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    if ($dg) {
        Save ($dg | Format-List * | Out-String) 'deviceguard.txt'
        $vbsNames = @('off', 'enabled but not running', 'running')
        $svcNames = @{ 1 = 'Credential Guard'; 2 = 'Memory integrity (HVCI)'; 3 = 'System Guard Secure Launch'; 4 = 'SMM firmware measurement'; 5 = 'Kernel-mode HW stack protection'; 7 = 'Hypervisor-enforced paging translation' }
        $running = @($dg.SecurityServicesRunning | Where-Object { $_ -ne 0 } | ForEach-Object { if ($svcNames.ContainsKey([int]$_)) { $svcNames[[int]$_] } else { 'service ' + $_ } })
        Note 'INFO' ('VBS {0}; running: {1}' -f $vbsNames[[int]$dg.VirtualizationBasedSecurityStatus], $(if ($running) { $running -join ', ' } else { 'none' }))
    }
    try {
        $bl = Get-BitLockerVolume -ErrorAction Stop
        Save ($bl | Format-List * | Out-String) 'bitlocker.txt'
        foreach ($v in $bl) { Note 'INFO' ('BitLocker {0}: {1}, protection {2}' -f $v.MountPoint, $v.VolumeStatus, $v.ProtectionStatus) }
    } catch { Note 'INFO' 'BitLocker: not queryable' }
}

Section 'Boot configuration (BCD)' {
    $bcd = (& bcdedit.exe /enum all /v) | Out-String
    Save $bcd 'bcd.txt'
    $checks = [ordered]@{
        'testsigning on (test-signed drivers allowed)' = '(?m)^testsigning\s+Yes'
        'nointegritychecks on'                         = '(?m)^nointegritychecks\s+Yes'
        'kernel debugging on'                          = '(?m)^debug\s+Yes'
        'boot debugging on'                            = '(?m)^bootdebug\s+Yes'
        'hypervisor debugging on'                      = '(?m)^hypervisordebug\s+Yes'
        'DISABLE_INTEGRITY_CHECKS load option'         = '(?im)DISABLE_INTEGRITY_CHECKS'
    }
    $bad = 0
    foreach ($k in $checks.Keys) { if ($bcd -match $checks[$k]) { Note 'FAIL' ('BCD: ' + $k); $bad++ } }
    if ($bcd -match '(?m)^loadoptions\s+(.+)$') { Note 'WARN' ('BCD: loadoptions set: ' + $Matches[1].Trim()); $bad++ }
    if ($bad -eq 0) { Note 'OK' 'BCD: no test-signing, debug or integrity-check overrides' }
}

Section 'Boot chain signatures (ESP + OS loader + kernel)' {
    $used = @((Get-PSDrive -PSProvider FileSystem).Name)
    $letter = [char[]](90..71) | Where-Object { $used -notcontains [string]$_ } | Select-Object -First 1
    $esp = '{0}:' -f $letter
    & mountvol.exe $esp /S | Out-Null
    $espRows = @()
    try {
        if (-not (Test-Path -LiteralPath ($esp + '\EFI'))) { throw 'could not mount the EFI System Partition' }
        Save (Get-ChildItem -LiteralPath ($esp + '\') -Recurse -Force | Select-Object FullName, Length, LastWriteTimeUtc | Format-Table -AutoSize | Out-String -Width 300) 'esp_listing.txt'
        foreach ($f in Get-ChildItem -LiteralPath ($esp + '\') -Recurse -File -Force) {
            $r = Get-SigRow $f.FullName 'ESP'
            $r.Path = 'ESP' + $f.FullName.Substring(2)
            $espRows += $r
        }
        $espDir = P 'esp_copies'
        New-Item -ItemType Directory -Force -Path $espDir | Out-Null
        foreach ($n in 'EFI\Microsoft\Boot\bootstat.dat', 'EFI\Microsoft\Boot\BCD') {
            try { Copy-Item -LiteralPath (Join-Path ($esp + '\') $n) -Destination $espDir -ErrorAction Stop } catch { }
        }
    } finally {
        & mountvol.exe $esp /D | Out-Null
    }
    $pe = $espRows | Where-Object { $_.Path -match '(?i)\.(efi|dll|exe|sys|mui)$' }
    $badPe = @($pe | Where-Object { $_.Status -ne 'Valid' })
    foreach ($r in $badPe) {
        $lvl = $(if ($r.Path -match '(?i)\.(efi|dll)$') { 'FAIL' } else { 'WARN' })
        Note $lvl ('ESP: {0} signature {1} {2}' -f $r.Path, $r.Status, $r.Signer)
    }
    foreach ($r in @($pe | Where-Object { $_.Status -eq 'Valid' -and -not (Test-Microsoft $_.Signer) })) { Note 'WARN' ('ESP: {0} signed by non-Microsoft {1}' -f $r.Path, $r.Signer) }
    Note $(if ($badPe.Count -eq 0) { 'OK' } else { 'FAIL' }) ('ESP: {0} files, {1} PE images, {2} without a valid signature' -f $espRows.Count, @($pe).Count, $badPe.Count)

    $sys = Join-Path $env:SystemRoot 'System32'
    $core = @('winload.efi', 'winresume.efi', 'ntoskrnl.exe', 'hal.dll', 'ci.dll', 'skci.dll', 'securekernel.exe', 'hvloader.efi', 'hvax64.exe', 'tcblaunch.exe', 'tcbloader.dll', 'kdcom.dll', 'bootvid.dll') |
        ForEach-Object { Join-Path $sys $_ }
    $core += Join-Path $env:SystemRoot 'Boot\EFI\bootmgfw.efi'
    $core += Join-Path $env:SystemRoot 'Boot\EFI_EX\bootmgfw_EX.efi'
    $coreRows = @($core | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object { Get-SigRow $_ 'core' })
    $badCore = @($coreRows | Where-Object { $_.Status -ne 'Valid' -or -not (Test-Microsoft $_.Signer) })
    foreach ($r in $badCore) { Note 'FAIL' ('core: {0} signature {1} {2}' -f $r.Path, $r.Status, $r.Signer) }
    if ($badCore.Count -eq 0) { Note 'OK' ('core: {0} loader/kernel files all Microsoft-signed' -f $coreRows.Count) }

    $espBm = $espRows | Where-Object { $_.Path -ieq 'ESP\EFI\Microsoft\Boot\bootmgfw.efi' } | Select-Object -First 1
    $srcHashes = @($coreRows | Where-Object { $_.Path -match '(?i)\\Boot\\EFI(_EX)?\\bootmgfw(_EX)?\.efi$' } | ForEach-Object { $_.SHA256 })
    if ($espBm) {
        if ($srcHashes -contains $espBm.SHA256) { Note 'OK' ('ESP bootmgfw.efi matches the copy under {0}\Boot (v{1})' -f $env:SystemRoot, $espBm.Version) }
        else { Note 'WARN' ('ESP bootmgfw.efi (v{0}, {1}) matches no copy under {2}\Boot' -f $espBm.Version, $espBm.Signer, $env:SystemRoot) }
    }
}

Section 'Drivers and services (signatures)' {
    $drvRows = @()
    foreach ($d in Get-CimInstance Win32_SystemDriver) {
        $p = ([string]$d.PathName).Trim('"') -replace '^\\\?\?\\', '' -replace '(?i)^\\SystemRoot', $env:SystemRoot
        if ($p -match '(?i)^system32\\') { $p = Join-Path $env:SystemRoot $p }
        $kind = 'driver {0} [{1}/{2}]' -f $d.Name, $d.StartMode, $d.State
        if ($p -and (Test-Path -LiteralPath $p)) { $drvRows += Get-SigRow $p $kind }
        elseif ($d.State -eq 'Running') { Note 'WARN' ('driver {0} is running but its file {1} was not found' -f $d.Name, $p) }
    }
    $script:DriverRows = $drvRows
    $badDrv = @($drvRows | Where-Object { $_.Status -ne 'Valid' -and $_.Kind -match '\[(Boot|System|Auto)/|/Running\]' })
    foreach ($r in $badDrv) { Note 'FAIL' ('{0}: {1} signature {2}' -f $r.Kind, $r.Path, $r.Status) }
    $third = @($drvRows | Where-Object { $_.Status -eq 'Valid' -and -not (Test-Microsoft $_.Signer) })
    Note $(if ($badDrv.Count -eq 0) { 'OK' } else { 'FAIL' }) ('drivers: {0} checked, {1} active without a valid signature, {2} signed by third parties (see third_party_drivers.txt)' -f $drvRows.Count, $badDrv.Count, $third.Count)
    Save ($third | Select-Object Kind, Path, Signer, Version | Format-Table -AutoSize | Out-String -Width 400) 'third_party_drivers.txt'

    $svcRows = @()
    $seen = @{}
    foreach ($s in Get-CimInstance Win32_Service) {
        if ([string]$s.PathName -notmatch '(?i)^\s*"?([^"]+?\.exe)') { continue }
        $exe = $Matches[1]
        if (-not (Test-Path -LiteralPath $exe)) { continue }
        if (-not $seen.ContainsKey($exe)) { $seen[$exe] = Get-SigRow $exe 'service-exe' }
        $r = $seen[$exe]
        $svcRows += [pscustomobject]@{ Name = $s.Name; DisplayName = $s.DisplayName; StartMode = $s.StartMode; State = $s.State; Exe = $exe; Status = $r.Status; Signer = $r.Signer }
    }
    $svcRows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (P 'services.csv')
    $badSvc = @($svcRows | Where-Object { $_.Status -ne 'Valid' -and ($_.StartMode -eq 'Auto' -or $_.State -eq 'Running') })
    foreach ($r in $badSvc) { Note 'WARN' ('service {0} ({1}) exe {2} signature {3}' -f $r.Name, $r.StartMode, $r.Exe, $r.Status) }
    $thirdSvc = @($svcRows | Where-Object { $_.Status -eq 'Valid' -and -not (Test-Microsoft $_.Signer) })
    Note $(if ($badSvc.Count -eq 0) { 'OK' } else { 'WARN' }) ('services: {0}, {1} auto/running without a valid signature, {2} third-party signed' -f $svcRows.Count, $badSvc.Count, $thirdSvc.Count)

    $script:SigRows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (P 'signatures.csv')
}

Section 'Crash and boot history (System log, 30 days)' {
    $want = @{
        'Microsoft-Windows-Kernel-Power'             = @(41, 42, 107, 109)
        'EventLog'                                   = @(6005, 6006, 6008)
        'Microsoft-Windows-Kernel-General'           = @(12, 13)
        'Microsoft-Windows-Kernel-Boot'              = @()
        'Microsoft-Windows-WER-SystemErrorReporting' = @()
        'BugCheck'                                   = @()
        'Microsoft-Windows-WHEA-Logger'              = @()
        'User32'                                     = @(1074, 1076)
        'volmgr'                                     = @()
        'Ntfs'                                       = @()
        'Microsoft-Windows-Ntfs'                     = @()
        'disk'                                       = @()
        'stornvme'                                   = @()
    }
    $all = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $Since } -ErrorAction SilentlyContinue
    $ev = @($all | Where-Object { $want.ContainsKey($_.ProviderName) -and ($want[$_.ProviderName].Count -eq 0 -or $want[$_.ProviderName] -contains $_.Id) })
    $rows = foreach ($e in $ev) {
        $msg = ''
        try { $msg = ($e.Message -split "`r?`n")[0] } catch { }
        [pscustomobject]@{ Time = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Provider = $e.ProviderName; Id = $e.Id; Level = $e.LevelDisplayName; Data = (Get-EvData $e); Message = $msg }
    }
    $rows = @($rows | Sort-Object Time)
    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (P 'boot_crash_events.csv')
    Save ($rows | Format-Table Time, Provider, Id, Message -AutoSize | Out-String -Width 400) 'boot_timeline.txt'

    $kp41 = @($rows | Where-Object { $_.Provider -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 41 })
    foreach ($r in ($kp41 | Select-Object -Last 15)) {
        $code = $(if ($r.Data -match 'BugcheckCode=(\d+)') { [uint32]$Matches[1] } else { 0 })
        $p1 = $(if ($r.Data -match 'BugcheckParameter1=(0x[0-9a-fA-F]+|\d+)') { $Matches[1] } else { '?' })
        if ($code -ne 0) { Note 'FAIL' ('{0} unexpected restart after BUGCHECK 0x{1:X} (param1 {2})' -f $r.Time, $code, $p1) }
        else { Note 'WARN' ('{0} unexpected restart without a bugcheck (reset/power loss before Windows could log one)' -f $r.Time) }
    }
    foreach ($r in @($rows | Where-Object { $_.Id -eq 1001 -and $_.Provider -match 'BugCheck|WER-SystemErrorReporting' })) { Note 'FAIL' ('{0} BugCheck record: {1}' -f $r.Time, $r.Message) }
    $whea = @($rows | Where-Object { $_.Provider -eq 'Microsoft-Windows-WHEA-Logger' })
    if ($whea.Count) { Note 'WARN' ('WHEA hardware errors: {0} (last {1})' -f $whea.Count, $whea[-1].Time) }
    $fs = @($rows | Where-Object { $_.Provider -match 'Ntfs|disk|stornvme|volmgr' -and $_.Level -match 'Error|Critical' })
    if ($fs.Count) { Note 'WARN' ('disk/NTFS/dump errors: {0} (last {1}: {2})' -f $fs.Count, $fs[-1].Time, $fs[-1].Message) }
    $boots = @($rows | Where-Object { $_.Provider -eq 'Microsoft-Windows-Kernel-General' -and $_.Id -eq 12 })
    Note 'INFO' ('{0} Windows starts in 30 days; {1} unexpected restarts (Kernel-Power 41); last good start before this one: {2}' -f $boots.Count, $kp41.Count, $(if ($boots.Count -ge 2) { $boots[-2].Time } else { 'none' }))

    foreach ($log in 'System', 'Application', 'Microsoft-Windows-CodeIntegrity/Operational', 'Microsoft-Windows-Kernel-Boot/Operational') {
        $f = P ('evtx_' + ($log -replace '[\\/ ]', '_') + '.evtx')
        & wevtutil.exe epl $log $f 2>$null
    }
    $ci = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; StartTime = $Since; Id = 3033, 3034, 3063, 3077, 3089 } -ErrorAction SilentlyContinue)
    if ($ci.Count) {
        $names = @($ci | ForEach-Object { if ((Get-EvData $_) -match 'FileNameBuffer=([^;]+)') { $Matches[1] } } | Sort-Object -Unique)
        Note 'WARN' ('Code Integrity refused/flagged {0} image loads (unsigned or bad hash): {1}' -f $ci.Count, (($names | Select-Object -First 8) -join ', '))
    } else { Note 'OK' 'Code Integrity: no blocked or bad-signature image loads in 30 days' }
}

Section 'Crash dumps' {
    $cc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    Note 'INFO' ('crash dump settings: CrashDumpEnabled={0} AutoReboot={1} DumpFile={2} MinidumpDir={3}' -f $cc.CrashDumpEnabled, $cc.AutoReboot, $cc.DumpFile, $cc.MinidumpDir)
    if ($cc.AutoReboot -ne 0) {
        Note 'INFO' 'AutoReboot is on: a bugcheck on the board reboots before the stop code can be read. To keep it on screen: reg add HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v AutoReboot /t REG_DWORD /d 0 /f'
    }
    $dumps = @()
    $dumps += @(Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'Minidump') -Filter *.dmp -Force -ErrorAction SilentlyContinue)
    $dumps += @(Get-Item -LiteralPath (Join-Path $env:SystemRoot 'MEMORY.DMP') -Force -ErrorAction SilentlyContinue)
    $dumps += @(Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'LiveKernelReports') -Recurse -Filter *.dmp -Force -ErrorAction SilentlyContinue)
    $rows = foreach ($d in ($dumps | Sort-Object LastWriteTime)) {
        [pscustomobject]@{ Time = $d.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); Size = $d.Length; Path = $d.FullName; Header = (Read-DumpHeader $d.FullName) }
    }
    Save ($rows | Format-Table -AutoSize | Out-String -Width 400) 'dumps.txt'
    foreach ($r in @($rows | Where-Object { [datetime]$_.Time -gt $Since })) { Note 'FAIL' ('dump {0} {1}: {2}' -f $r.Time, $r.Path, $r.Header) }
    if (-not @($rows).Count) { Note 'OK' 'no crash dumps (Minidump, MEMORY.DMP, LiveKernelReports)' }
    $dumpDir = P 'minidumps'
    $mini = @($dumps | Where-Object { $_.Length -lt 64MB } | Sort-Object LastWriteTime | Select-Object -Last 5)
    if ($mini.Count) {
        New-Item -ItemType Directory -Force -Path $dumpDir | Out-Null
        foreach ($m in $mini) { Copy-Item -LiteralPath $m.FullName -Destination $dumpDir -ErrorAction SilentlyContinue }
    }
}

Section 'Startup repair, boot status, measured boot logs' {
    $srt = Join-Path $env:SystemRoot 'System32\LogFiles\Srt\SrtTrail.txt'
    if (Test-Path -LiteralPath $srt) { Copy-Item -LiteralPath $srt -Destination (P 'SrtTrail.txt'); Note 'INFO' ('Startup Repair ran (SrtTrail.txt {0})' -f (Get-Item $srt).LastWriteTime) }
    $bs = Join-Path $env:SystemRoot 'bootstat.dat'
    if (Test-Path -LiteralPath $bs) { try { Copy-Item -LiteralPath $bs -Destination (P 'bootstat_windows.dat') -ErrorAction Stop } catch { } }

    $mb = Join-Path $env:SystemRoot 'Logs\MeasuredBoot'
    $logs = @(Get-ChildItem -LiteralPath $mb -Filter *.log -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)
    Save ($logs | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize | Out-String) 'measuredboot_list.txt'
    if ($logs.Count) {
        $dst = P 'measuredboot'
        New-Item -ItemType Directory -Force -Path $dst | Out-Null
        foreach ($l in ($logs | Select-Object -Last 40)) { Copy-Item -LiteralPath $l.FullName -Destination $dst -ErrorAction SilentlyContinue }
        Note 'INFO' ('measured boot (TCG) logs: {0}, newest 40 copied (one per boot that reached Windows)' -f $logs.Count)
    }
}

Section 'Fast Startup, hibernation, volume state' {
    $hb = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction SilentlyContinue).HiberbootEnabled
    if ($hb -eq 1) { Note 'WARN' 'Fast Startup is ON: shutdown leaves C: hibernated, and Linux writing to it then corrupts NTFS (2026-10-09). Off: powercfg /h off' }
    else { Note 'OK' 'Fast Startup off' }
    Save ((& powercfg.exe /a) | Out-String) 'power_states.txt'
    $dirty = (& fsutil.exe dirty query $env:SystemDrive) | Out-String
    if ($dirty -match 'NOT Dirty') { Note 'OK' ('{0} not marked dirty' -f $env:SystemDrive) } else { Note 'WARN' ('{0}: {1}' -f $env:SystemDrive, $dirty.Trim()) }
    Save (Get-Volume | Format-Table -AutoSize | Out-String -Width 300) 'volumes.txt'
}

Section 'Firmware-supplied and vendor software (WPBT, ASUS)' {
    $wpbt = Join-Path $env:SystemRoot 'System32\wpbbin.exe'
    if (Test-Path -LiteralPath $wpbt) {
        $r = Get-SigRow $wpbt 'wpbt'
        Note 'WARN' ('wpbbin.exe present: a program supplied by the firmware (WPBT) that Windows ran at boot. Signer {0}, {1}, {2}' -f $r.Signer, $r.Version, $r.Modified)
    } else { Note 'OK' 'no wpbbin.exe: no firmware-supplied (WPBT) program has run' }
    $dw = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue).DisableWpbtExecution
    Note 'INFO' ('DisableWpbtExecution = {0}' -f $(if ($null -eq $dw) { 'not set' } else { $dw }))
    $re = '(?i)asus|armoury|aura|glidex|\brog\b|asusrog|ac(c)?x|lightingservice|myasus'
    $svc = @(Get-CimInstance Win32_Service | Where-Object { ('{0} {1} {2}' -f $_.Name, $_.DisplayName, $_.PathName) -match $re })
    $pkg = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $re })
    $drv = @($script:DriverRows | Where-Object { $_.Signer -match '(?i)asus' })
    Save (($svc | Select-Object Name, DisplayName, StartMode, State, PathName | Format-Table -AutoSize | Out-String -Width 400) +
          ($pkg | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize | Out-String -Width 400) +
          ($drv | Select-Object Kind, Path, Version | Format-Table -AutoSize | Out-String -Width 400)) 'vendor_asus.txt'
    if ($svc.Count + $pkg.Count + $drv.Count) { Note 'INFO' ('ASUS software: {0} services, {1} installed packages, {2} ASUS-signed drivers (vendor_asus.txt)' -f $svc.Count, $pkg.Count, $drv.Count) }
    else { Note 'OK' 'no ASUS services, packages or drivers' }
}

Section 'Autostart and persistence' {
    $lines = New-Object System.Collections.Generic.List[string]
    $runKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    $nRun = 0
    foreach ($k in $runKeys) {
        $p = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        foreach ($prop in $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) { $lines.Add(('{0} : {1} = {2}' -f $k, $prop.Name, $prop.Value)); $nRun++ }
    }
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if ($wl.Shell -ne 'explorer.exe') { Note 'WARN' ('Winlogon Shell = {0}' -f $wl.Shell) }
    if ($wl.Userinit -notmatch '^(?i)C:\\Windows\\system32\\userinit\.exe,?$') { Note 'WARN' ('Winlogon Userinit = {0}' -f $wl.Userinit) }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $a = (Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue).AppInit_DLLs
        if ($a) { Note 'WARN' ('AppInit_DLLs set in {0}: {1}' -f $k, $a) }
    }
    $ifeo = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue |
        ForEach-Object { $d = (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).Debugger; if ($d) { '{0} -> {1}' -f $_.PSChildName, $d } })
    foreach ($i in $ifeo) { Note 'WARN' ('IFEO debugger hijack: ' + $i) }

    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })
    foreach ($t in $tasks) {
        $acts = ($t.Actions | ForEach-Object { ('{0} {1}' -f $_.Execute, $_.Arguments).Trim() }) -join ' | '
        $lines.Add(('task {0}{1} [{2}] : {3}' -f $t.TaskPath, $t.TaskName, $t.State, $acts))
    }

    $filters = @(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue)
    $consumers = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue)
    foreach ($c in $consumers) {
        $lines.Add(('wmi consumer {0} {1} : {2}{3}' -f $c.CimClass.CimClassName, $c.Name, $c.CommandLineTemplate, $c.ScriptText))
        if ($c.CimClass.CimClassName -match 'CommandLineEventConsumer|ActiveScriptEventConsumer') { Note 'WARN' ('WMI persistence: {0} "{1}" runs {2}{3}' -f $c.CimClass.CimClassName, $c.Name, $c.CommandLineTemplate, $c.ScriptText) }
    }
    foreach ($f in $filters) { $lines.Add(('wmi filter {0} : {1}' -f $f.Name, $f.Query)) }

    foreach ($dir in (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'), (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')) {
        Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object { $lines.Add(('startup folder: {0}' -f $_.FullName)) }
    }
    Save $lines 'autostart.txt'
    Note 'INFO' ('autostart: {0} Run/RunOnce values, {1} non-Microsoft scheduled tasks, {2} WMI consumers (autostart.txt)' -f $nRun, $tasks.Count, $consumers.Count)

    $hosts = Get-Content (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*[^#\s]' }
    if ($hosts) { Note 'WARN' ('hosts file has {0} active entries: {1}' -f @($hosts).Count, ((@($hosts) | Select-Object -First 5) -join ' / ')) } else { Note 'OK' 'hosts file has no active entries' }

    Save (Get-ChildItem Cert:\LocalMachine\Root | Select-Object Subject, Thumbprint, NotAfter | Sort-Object Subject | Format-Table -AutoSize | Out-String -Width 400) 'root_certs.txt'
}

Section 'Microsoft Defender' {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    Save ($mp | Format-List * | Out-String) 'defender.txt'
    Note $(if ($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled) { 'OK' } else { 'WARN' }) ('Defender: AV {0}, real-time {1}, tamper protection {2}, signatures {3}' -f $mp.AntivirusEnabled, $mp.RealTimeProtectionEnabled, $mp.IsTamperProtected, $mp.AntivirusSignatureLastUpdated)
    $pref = Get-MpPreference
    $ex = @($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension) | Where-Object { $_ }
    if ($ex) { Note 'WARN' ('Defender exclusions: {0}' -f ($ex -join ', ')) } else { Note 'OK' 'Defender: no exclusions' }
    $det = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt $Since })
    if ($det.Count) {
        Save ($det | Format-List * | Out-String) 'defender_detections.txt'
        Note 'WARN' ('Defender detections in 30 days: {0} (defender_detections.txt)' -f $det.Count)
    }
}

if ($Full) {
    Section 'File system (online chkdsk scan)' {
        $r = Repair-Volume -DriveLetter $env:SystemDrive[0] -Scan
        Note $(if ([string]$r -eq 'NoErrorsFound') { 'OK' } else { 'WARN' }) ('chkdsk /scan {0}: {1}' -f $env:SystemDrive, $r)
    }
    Section 'System files (sfc /verifyonly)' {
        $o = ((& sfc.exe /verifyonly) -join "`n") -replace "`0", ''
        Save $o 'sfc.txt'
        if ($o -match 'did not find any integrity violations') { Note 'OK' 'sfc: no integrity violations' }
        elseif ($o -match 'found integrity violations') { Note 'FAIL' 'sfc: integrity violations found (sfc.txt, C:\Windows\Logs\CBS\CBS.log)' }
        else { Note 'WARN' 'sfc: unclear result (sfc.txt)' }
    }
    Section 'Component store (DISM /ScanHealth)' {
        $o = (& dism.exe /English /Online /Cleanup-Image /ScanHealth) -join "`n"
        Save $o 'dism.txt'
        if ($o -match 'No component store corruption detected') { Note 'OK' 'DISM: no component store corruption' }
        elseif ($o -match 'repairable') { Note 'FAIL' 'DISM: component store corruption (repairable), see dism.txt' }
        else { Note 'WARN' 'DISM: unclear result (dism.txt)' }
    }
}

# ------------------------------------------------------------------------------------------------
$Summary | Out-File -Encoding utf8 -FilePath (P 'summary.txt')
'complete' | Out-File -Encoding ascii -FilePath (P 'DONE')
try { Write-VolumeCache -DriveLetter $XferRoot[0] -ErrorAction Stop } catch { }
$nf = @($Summary | Where-Object { $_ -like '`[FAIL`]*' }).Count
$nw = @($Summary | Where-Object { $_ -like '`[WARN`]*' }).Count
Write-Host ''
Write-Host ('Finished: {0} FAIL, {1} WARN. Report: {2}' -f $nf, $nw, $Out) -ForegroundColor Cyan
Write-Host 'Leave this drive plugged in; on Linux run: sudo ./inspect.sh collect' -ForegroundColor Cyan
