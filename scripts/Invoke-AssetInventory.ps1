#requires -Version 3.0
<#
.SYNOPSIS
    Asset inventory for ConnectWise Automate agents: hardware, installed and running
    software, live system resources, and (optionally) discovery of every device on the
    agent's network.

.DESCRIPTION
    Designed to be run by the Automate agent (LocalSystem) through a script step, but it
    runs fine interactively from an elevated PowerShell prompt too.

    Scope Local   - inventory this computer only (default; safe to run on every agent).
    Scope Network - discover devices on the local subnet(s) only.
    Scope Full    - both. Run this on ONE agent per site/VLAN (your "probe" machine).

    Output (written to -OutputPath, file names are stable so Automate can upload them):
        <COMPUTER>_inventory.json          everything, machine readable
        <COMPUTER>_inventory.html          self-contained report
        <COMPUTER>_software.csv            installed software
        <COMPUTER>_processes.csv           running processes
        <COMPUTER>_services.csv            services
        <COMPUTER>_network_devices.csv     discovered devices (Network/Full scope)

    A short summary is written to stdout (captured by Automate in %shellresult%).
    The last line is RESULT=SUCCESS or RESULT=FAILED: <reason>.

    The script is read-only: it changes nothing on the machine apart from writing its
    report files. Network discovery sends ICMP echo requests and a handful of TCP
    connection attempts to each address in the local subnet(s).

.PARAMETER Scope
    Local, Network or Full. Default Local.

.PARAMETER OutputPath
    Folder for the report files. Default: %windir%\LTSvc\AssetInventory when the Automate
    agent is installed, otherwise %ProgramData%\AssetInventory.

.PARAMETER Subnet
    Comma-separated CIDR ranges to scan instead of the auto-detected local subnets,
    e.g. "192.168.1.0/24,10.0.20.0/24".

.PARAMETER MaxHostsPerSubnet
    Safety cap. A larger subnet is narrowed to the /24 around this machine (or truncated
    for ranges given with -Subnet). Default 1024.

.PARAMETER ProbePorts
    Comma-separated TCP ports checked on each discovered device to guess what it is.

.PARAMETER OuiFile
    Optional path to the IEEE OUI list (oui.csv from standards-oui.ieee.org) to resolve
    MAC addresses to a manufacturer.

.PARAMETER SampleSeconds
    How long to sample CPU / disk / network activity. Default 5.

.PARAMETER IncludeCommandLine
    Include process command lines. Off by default because command lines can contain
    passwords and tokens.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Invoke-AssetInventory.ps1

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Invoke-AssetInventory.ps1 -Scope Full -Subnet "10.0.20.0/24"
#>
[CmdletBinding()]
param(
    [ValidateSet('Local', 'Network', 'Full')]
    [string]$Scope = 'Local',
    [string]$OutputPath,
    [string]$Subnet,
    [int]$MaxHostsPerSubnet = 1024,
    [int]$PingTimeoutMs = 750,
    [string]$ProbePorts = '22,80,135,443,445,3389,9100',
    [int]$PortTimeoutMs = 600,
    [string]$OuiFile,
    [int]$SampleSeconds = 5,
    [int]$TopProcessCount = 15,
    [switch]$IncludeCommandLine,
    [switch]$NoHtml,
    [switch]$NoCsv
)

$script:Errors = New-Object System.Collections.ArrayList

# ----------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------

function Get-Wmi {
    # CIM first, WMI as a fallback (older agents / broken WinRM-less CIM). Never throws.
    param([string]$Class, [string]$Namespace = 'root\cimv2', [string]$Filter)
    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        try {
            $p = @{ ClassName = $Class; Namespace = $Namespace; ErrorAction = 'Stop' }
            if ($Filter) { $p.Filter = $Filter }
            return @(Get-CimInstance @p)
        } catch { }
    }
    if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
        try {
            $p = @{ Class = $Class; Namespace = $Namespace; ErrorAction = 'Stop' }
            if ($Filter) { $p.Filter = $Filter }
            return @(Get-WmiObject @p)
        } catch { }
    }
    return @()
}

function Invoke-Section {
    # Runs one inventory section; a failure is recorded and never aborts the whole run.
    param([string]$Name, [scriptblock]$Script)
    try { & $Script }
    catch {
        [void]$script:Errors.Add(('{0}: {1}' -f $Name, $_.Exception.Message))
        $null
    }
}

function ConvertTo-IsoDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToString('s') }
    $s = [string]$Value
    if ($s -match '^\d{14}\.\d{6}[+-]\d{3}$') {
        try { return [System.Management.ManagementDateTimeConverter]::ToDateTime($s).ToString('s') } catch { }
    }
    if ($s -match '^(\d{4})(\d{2})(\d{2})$') { return ('{0}-{1}-{2}' -f $Matches[1], $Matches[2], $Matches[3]) }
    return $null
}

function ConvertTo-GB { param($Bytes, [int]$Digits = 2) if ($null -eq $Bytes) { return $null } [math]::Round(([double]$Bytes / 1GB), $Digits) }
function ConvertTo-MB { param($Bytes, [int]$Digits = 1) if ($null -eq $Bytes) { return $null } [math]::Round(([double]$Bytes / 1MB), $Digits) }

function Get-Trimmed { param($Value) if ($null -eq $Value) { return $null } ([string]$Value).Trim() }

function Get-Percent {
    param($Part, $Whole, [int]$Digits = 1)
    if (-not $Whole -or [double]$Whole -eq 0) { return $null }
    [math]::Round(([double]$Part / [double]$Whole) * 100, $Digits)
}

function ConvertFrom-ByteString {
    # WmiMonitorID stores strings as zero padded uint16 arrays.
    param($Bytes)
    if (-not $Bytes) { return $null }
    $chars = foreach ($b in $Bytes) { if ([int]$b -gt 0) { [char][int]$b } }
    (-join $chars).Trim()
}

function Format-Mac {
    param([string]$Mac)
    if (-not $Mac) { return $null }
    $hex = ($Mac -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($hex.Length -ne 12) { return $null }
    (($hex -split '(.{2})' | Where-Object { $_ }) -join ':')
}

# ----------------------------------------------------------------------------------
# IPv4 maths
# ----------------------------------------------------------------------------------

function ConvertTo-IPNumber {
    param([string]$Ip)
    $b = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes()
    if ($b.Length -ne 4) { throw "Not an IPv4 address: $Ip" }
    [uint64](([uint64]$b[0] * 16777216) + ([uint64]$b[1] * 65536) + ([uint64]$b[2] * 256) + [uint64]$b[3])
}

function ConvertFrom-IPNumber {
    param([uint64]$Number)
    '{0}.{1}.{2}.{3}' -f (($Number -shr 24) -band 255), (($Number -shr 16) -band 255), (($Number -shr 8) -band 255), ($Number -band 255)
}

function ConvertTo-PrefixLength {
    param([string]$Mask)
    $n = ConvertTo-IPNumber $Mask
    $bits = 0
    for ($i = 31; $i -ge 0; $i--) { if (($n -shr $i) -band 1) { $bits++ } else { break } }
    $bits
}

function Get-SubnetRange {
    # Returns the usable host range of a network as numbers.
    param([string]$Ip, [int]$Prefix)
    if ($Prefix -lt 0 -or $Prefix -gt 32) { throw "Invalid prefix length: $Prefix" }
    $ipNum = ConvertTo-IPNumber $Ip
    $size = [uint64][math]::Pow(2, 32 - $Prefix)
    $network = $ipNum - ($ipNum % $size)
    $broadcast = $network + $size - 1
    if ($Prefix -ge 31) { $first = $network; $last = $broadcast }
    else { $first = $network + 1; $last = $broadcast - 1 }
    [pscustomobject]@{
        Cidr      = '{0}/{1}' -f (ConvertFrom-IPNumber $network), $Prefix
        Network   = $network
        Broadcast = $broadcast
        First     = $first
        Last      = $last
        HostCount = [int64]($last - $first + 1)
    }
}

# ----------------------------------------------------------------------------------
# Hardware
# ----------------------------------------------------------------------------------

function Get-SystemInfo {
    $cs = Get-Wmi Win32_ComputerSystem | Select-Object -First 1
    $os = Get-Wmi Win32_OperatingSystem | Select-Object -First 1
    $bios = Get-Wmi Win32_BIOS | Select-Object -First 1
    $enc = Get-Wmi Win32_SystemEnclosure | Select-Object -First 1
    $prod = Get-Wmi Win32_ComputerSystemProduct | Select-Object -First 1
    $board = Get-Wmi Win32_BaseBoard | Select-Object -First 1

    $chassisNames = @{
        1 = 'Other'; 2 = 'Unknown'; 3 = 'Desktop'; 4 = 'Low Profile Desktop'; 5 = 'Pizza Box'; 6 = 'Mini Tower'
        7 = 'Tower'; 8 = 'Portable'; 9 = 'Laptop'; 10 = 'Notebook'; 11 = 'Hand Held'; 12 = 'Docking Station'
        13 = 'All in One'; 14 = 'Sub Notebook'; 15 = 'Space-Saving'; 16 = 'Lunch Box'; 17 = 'Main System Chassis'
        18 = 'Expansion Chassis'; 19 = 'SubChassis'; 20 = 'Bus Expansion Chassis'; 21 = 'Peripheral Chassis'
        22 = 'Storage Chassis'; 23 = 'Rack Mount Chassis'; 24 = 'Sealed-Case PC'; 30 = 'Tablet'; 31 = 'Convertible'
        32 = 'Detachable'; 35 = 'Mini PC'; 36 = 'Stick PC'
    }
    $chassis = $null
    if ($enc -and $enc.ChassisTypes) {
        $code = [int](@($enc.ChassisTypes)[0])
        $chassis = if ($chassisNames.ContainsKey($code)) { $chassisNames[$code] } else { "Type $code" }
    }

    $domainRoles = @('Standalone Workstation', 'Member Workstation', 'Standalone Server', 'Member Server', 'Backup Domain Controller', 'Primary Domain Controller')
    $role = $null
    if ($cs -and $null -ne $cs.DomainRole -and [int]$cs.DomainRole -lt $domainRoles.Count) { $role = $domainRoles[[int]$cs.DomainRole] }

    $isVirtual = $false
    if ($cs) {
        $sig = '{0} {1}' -f $cs.Manufacturer, $cs.Model
        if ($sig -match 'VMware|VirtualBox|innotek|KVM|QEMU|Xen|HVM domU|Parallels|Virtual Machine|Bochs|Nutanix|oVirt|Google Compute|Amazon EC2') { $isVirtual = $true }
    }

    $lastBoot = $null; $uptimeDays = $null
    if ($os -and $os.LastBootUpTime) {
        $lastBoot = ConvertTo-IsoDate $os.LastBootUpTime
        if ($lastBoot) { $uptimeDays = [math]::Round(((Get-Date) - [datetime]$lastBoot).TotalDays, 2) }
    }

    $tz = $null
    try { $tz = [System.TimeZoneInfo]::Local.Id } catch { }

    [pscustomobject]@{
        ComputerName      = if ($cs -and $cs.Name) { $cs.Name } else { [System.Environment]::MachineName }
        Domain            = if ($cs) { $cs.Domain } else { $null }
        PartOfDomain      = if ($cs) { [bool]$cs.PartOfDomain } else { $null }
        DomainRole        = $role
        Manufacturer      = Get-Trimmed $cs.Manufacturer
        Model             = Get-Trimmed $cs.Model
        SystemFamily      = Get-Trimmed $cs.SystemFamily
        SystemSKU         = Get-Trimmed $cs.SystemSKUNumber
        SerialNumber      = Get-Trimmed $bios.SerialNumber
        AssetTag          = Get-Trimmed $enc.SMBIOSAssetTag
        UUID              = Get-Trimmed $prod.UUID
        ChassisType       = $chassis
        IsVirtual         = $isVirtual
        BiosVendor        = Get-Trimmed $bios.Manufacturer
        BiosVersion       = Get-Trimmed $bios.SMBIOSBIOSVersion
        BiosReleaseDate   = ConvertTo-IsoDate $bios.ReleaseDate
        Motherboard       = if ($board) { ('{0} {1}' -f $board.Manufacturer, $board.Product).Trim() } else { $null }
        MotherboardSerial = Get-Trimmed $board.SerialNumber
        OSName            = Get-Trimmed $os.Caption
        OSVersion         = $os.Version
        OSBuild           = $os.BuildNumber
        OSArchitecture    = $os.OSArchitecture
        OSInstallDate     = ConvertTo-IsoDate $os.InstallDate
        OSLanguage        = $os.MUILanguages -join ', '
        LastBootTime      = $lastBoot
        UptimeDays        = $uptimeDays
        TimeZone          = $tz
        LoggedOnUser      = if ($cs) { $cs.UserName } else { $null }
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}

function Get-CpuInfo {
    @(Get-Wmi Win32_Processor | ForEach-Object {
            [pscustomobject]@{
                Socket            = $_.SocketDesignation
                Name              = Get-Trimmed $_.Name
                Manufacturer      = $_.Manufacturer
                Cores             = $_.NumberOfCores
                LogicalProcessors = $_.NumberOfLogicalProcessors
                MaxClockMHz       = $_.MaxClockSpeed
                CurrentClockMHz   = $_.CurrentClockSpeed
                L2CacheKB         = $_.L2CacheSize
                L3CacheKB         = $_.L3CacheSize
                Virtualization    = $_.VirtualizationFirmwareEnabled
            }
        })
}

function Get-MemoryInfo {
    $typeNames = @{ 20 = 'DDR'; 21 = 'DDR2'; 22 = 'DDR2 FB-DIMM'; 24 = 'DDR3'; 26 = 'DDR4'; 27 = 'LPDDR'; 28 = 'LPDDR2'; 29 = 'LPDDR3'; 30 = 'LPDDR4'; 34 = 'DDR5'; 35 = 'LPDDR5' }
    $formNames = @{ 8 = 'DIMM'; 12 = 'SODIMM'; 13 = 'SRIMM'; 9 = 'TSOP' }
    $modules = @(Get-Wmi Win32_PhysicalMemory | ForEach-Object {
            $t = [int]$_.SMBIOSMemoryType
            $f = [int]$_.FormFactor
            [pscustomobject]@{
                Slot         = $_.DeviceLocator
                Bank         = $_.BankLabel
                CapacityGB   = ConvertTo-GB $_.Capacity
                Type         = if ($typeNames.ContainsKey($t)) { $typeNames[$t] } else { $null }
                FormFactor   = if ($formNames.ContainsKey($f)) { $formNames[$f] } else { $null }
                SpeedMHz     = $_.Speed
                Manufacturer = Get-Trimmed $_.Manufacturer
                PartNumber   = Get-Trimmed $_.PartNumber
                SerialNumber = Get-Trimmed $_.SerialNumber
            }
        })
    $arrays = @(Get-Wmi Win32_PhysicalMemoryArray)
    $slots = 0; $maxKb = 0
    foreach ($a in $arrays) { $slots += [int]$a.MemoryDevices; $maxKb += [double]$a.MaxCapacity }
    $os = Get-Wmi Win32_OperatingSystem | Select-Object -First 1
    $installed = 0
    foreach ($m in $modules) { $installed += [double]$m.CapacityGB }
    [pscustomobject]@{
        InstalledGB   = [math]::Round($installed, 2)
        UsableGB      = if ($os) { [math]::Round(([double]$os.TotalVisibleMemorySize * 1KB) / 1GB, 2) } else { $null }
        SlotsTotal    = if ($slots) { $slots } else { $null }
        SlotsUsed     = $modules.Count
        MaxCapacityGB = if ($maxKb) { [math]::Round(($maxKb * 1KB) / 1GB, 0) } else { $null }
        Modules       = $modules
    }
}

function Get-StorageInfo {
    $mediaNames = @{ 0 = 'Unspecified'; 3 = 'HDD'; 4 = 'SSD'; 5 = 'SCM' }
    $healthNames = @{ 0 = 'Healthy'; 1 = 'Warning'; 2 = 'Unhealthy'; 5 = 'Unknown' }
    $busNames = @{ 1 = 'SCSI'; 2 = 'ATAPI'; 3 = 'ATA'; 6 = 'Fibre Channel'; 7 = 'USB'; 8 = 'RAID'; 9 = 'iSCSI'; 10 = 'SAS'; 11 = 'SATA'; 12 = 'SD'; 13 = 'MMC'; 15 = 'File Backed Virtual'; 16 = 'Storage Spaces'; 17 = 'NVMe' }

    # Windows 8 / Server 2012 and later expose media type and health here.
    $modern = @{}
    foreach ($pd in (Get-Wmi MSFT_PhysicalDisk 'root\Microsoft\Windows\Storage')) { $modern[[string]$pd.DeviceId] = $pd }

    $physical = @(Get-Wmi Win32_DiskDrive | Sort-Object Index | ForEach-Object {
            $pd = $modern[[string]$_.Index]
            $media = $null; $health = $null; $bus = $_.InterfaceType
            if ($pd) {
                $mt = [int]$pd.MediaType; $hs = [int]$pd.HealthStatus; $bt = [int]$pd.BusType
                if ($mediaNames.ContainsKey($mt)) { $media = $mediaNames[$mt] }
                if ($healthNames.ContainsKey($hs)) { $health = $healthNames[$hs] }
                if ($busNames.ContainsKey($bt)) { $bus = $busNames[$bt] }
            }
            [pscustomobject]@{
                Index        = $_.Index
                Model        = Get-Trimmed $_.Model
                SerialNumber = Get-Trimmed $_.SerialNumber
                Firmware     = Get-Trimmed $_.FirmwareRevision
                SizeGB       = ConvertTo-GB $_.Size
                MediaType    = $media
                BusType      = $bus
                Partitions   = $_.Partitions
                Health       = $health
                SmartStatus  = $_.Status
            }
        })

    $volumes = @(Get-Wmi Win32_LogicalDisk -Filter 'DriveType=3' | Sort-Object DeviceID | ForEach-Object {
            [pscustomobject]@{
                Drive       = $_.DeviceID
                Label       = $_.VolumeName
                FileSystem  = $_.FileSystem
                SizeGB      = ConvertTo-GB $_.Size
                FreeGB      = ConvertTo-GB $_.FreeSpace
                UsedGB      = ConvertTo-GB ([double]$_.Size - [double]$_.FreeSpace)
                FreePercent = Get-Percent $_.FreeSpace $_.Size
            }
        })

    [pscustomobject]@{ PhysicalDisks = $physical; Volumes = $volumes }
}

function Get-DisplayInfo {
    $gpus = @(Get-Wmi Win32_VideoController | ForEach-Object {
            [pscustomobject]@{
                Name          = Get-Trimmed $_.Name
                DriverVersion = $_.DriverVersion
                DriverDate    = ConvertTo-IsoDate $_.DriverDate
                # AdapterRAM is a 32-bit field, so cards with more than 4 GB under-report.
                AdapterRamGB  = ConvertTo-GB $_.AdapterRAM
                Resolution    = if ($_.CurrentHorizontalResolution) { '{0}x{1}' -f $_.CurrentHorizontalResolution, $_.CurrentVerticalResolution } else { $null }
            }
        })
    $monitors = @(Get-Wmi WmiMonitorID 'root\wmi' | ForEach-Object {
            [pscustomobject]@{
                Manufacturer = ConvertFrom-ByteString $_.ManufacturerName
                Model        = ConvertFrom-ByteString $_.UserFriendlyName
                SerialNumber = ConvertFrom-ByteString $_.SerialNumberID
                Year         = $_.YearOfManufacture
            }
        })
    [pscustomobject]@{ VideoControllers = $gpus; Monitors = $monitors }
}

function Get-NetworkAdapterInfo {
    $nics = @{}
    foreach ($n in (Get-Wmi Win32_NetworkAdapter)) { $nics[[string]$n.Index] = $n }
    @(Get-Wmi Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | ForEach-Object {
            $n = $nics[[string]$_.Index]
            $v4 = @(); $v6 = @(); $masks = @()
            $addresses = @($_.IPAddress); $subnets = @($_.IPSubnet)
            for ($i = 0; $i -lt $addresses.Count; $i++) {
                if ($addresses[$i] -match '^\d+\.\d+\.\d+\.\d+$') { $v4 += $addresses[$i]; if ($i -lt $subnets.Count) { $masks += $subnets[$i] } }
                elseif ($addresses[$i]) { $v6 += $addresses[$i] }
            }
            [pscustomobject]@{
                Name        = if ($n -and $n.NetConnectionID) { $n.NetConnectionID } else { $_.Description }
                Description = $_.Description
                MacAddress  = Format-Mac $_.MACAddress
                IPv4        = $v4
                SubnetMask  = $masks
                IPv6        = $v6
                Gateway     = @($_.DefaultIPGateway | Where-Object { $_ })
                DnsServers  = @($_.DNSServerSearchOrder | Where-Object { $_ })
                DhcpEnabled = [bool]$_.DHCPEnabled
                DhcpServer  = $_.DHCPServer
                DnsSuffix   = $_.DNSDomain
                SpeedMbps   = if ($n -and $n.Speed -and [double]$n.Speed -lt 1e12) { [math]::Round([double]$n.Speed / 1e6, 0) } else { $null }
                Physical    = if ($n) { [bool]$n.PhysicalAdapter } else { $null }
            }
        })
}

function Get-PeripheralInfo {
    $printers = @(Get-Wmi Win32_Printer | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; Driver = $_.DriverName; Port = $_.PortName; Shared = [bool]$_.Shared; Default = [bool]$_.Default; Network = [bool]$_.Network }
        })
    $batteries = @(Get-Wmi Win32_Battery | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; ChargePercent = $_.EstimatedChargeRemaining; Status = $_.Status; Chemistry = $_.Chemistry }
        })
    [pscustomobject]@{ Printers = $printers; Batteries = $batteries }
}

function Get-SecurityInfo {
    $tpm = Get-Wmi Win32_Tpm 'root\cimv2\Security\MicrosoftTpm' | Select-Object -First 1
    $secureBoot = $null
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $secureBoot = $null }
    }
    $protection = @{ 0 = 'Off'; 1 = 'On'; 2 = 'Unknown' }
    $bitlocker = @(Get-Wmi Win32_EncryptableVolume 'root\cimv2\Security\MicrosoftVolumeEncryption' | Where-Object { $_.DriveLetter } | ForEach-Object {
            $ps = [int]$_.ProtectionStatus
            [pscustomobject]@{ Drive = $_.DriveLetter; Protection = if ($protection.ContainsKey($ps)) { $protection[$ps] } else { "$ps" } }
        })
    # SecurityCenter2 only exists on workstation editions.
    $av = @(Get-Wmi AntiVirusProduct 'root\SecurityCenter2' | ForEach-Object {
            $state = [int]$_.productState
            [pscustomobject]@{
                Name     = $_.displayName
                Enabled  = (($state -shr 12) -band 1) -eq 1
                UpToDate = (($state -shr 4) -band 1) -eq 0
            }
        })
    [pscustomobject]@{
        TpmPresent  = [bool]$tpm
        TpmVersion  = if ($tpm) { ([string]$tpm.SpecVersion -split ',')[0] } else { $null }
        TpmEnabled  = if ($tpm) { [bool]$tpm.IsEnabled_InitialValue } else { $null }
        SecureBoot  = $secureBoot
        BitLocker   = $bitlocker
        Antivirus   = $av
    }
}

# ----------------------------------------------------------------------------------
# Software
# ----------------------------------------------------------------------------------

function Get-InstalledSoftware {
    # Read from the registry. Win32_Product is deliberately avoided: it is slow and
    # triggers an MSI consistency check/repair on every installed package.
    $roots = New-Object System.Collections.ArrayList
    [void]$roots.Add(@{ Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Arch = 'x64'; Scope = 'Machine' })
    [void]$roots.Add(@{ Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Arch = 'x86'; Scope = 'Machine' })
    if (-not (Test-Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node')) { $roots[0].Arch = 'x86' }

    # Per-user installs for every profile whose hive is currently loaded.
    foreach ($hive in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        $sid = $hive.PSChildName
        if ($sid -notmatch '^S-1-5-21-[\d-]+$') { continue }
        $user = $sid
        try { $user = (New-Object System.Security.Principal.SecurityIdentifier $sid).Translate([System.Security.Principal.NTAccount]).Value } catch { }
        [void]$roots.Add(@{ Path = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall"; Arch = $null; Scope = "User: $user" })
    }

    $seen = @{}
    $items = foreach ($root in $roots) {
        if (-not (Test-Path $root.Path)) { continue }
        foreach ($key in @(Get-ChildItem $root.Path -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if (-not $p -or -not $p.DisplayName) { continue }
            if ($p.SystemComponent -eq 1 -or $p.ParentKeyName) { continue }
            if ($p.ReleaseType -match 'Update|Hotfix') { continue }
            $id = '{0}|{1}|{2}' -f $p.DisplayName, $p.DisplayVersion, $root.Scope
            if ($seen.ContainsKey($id)) { continue }
            $seen[$id] = $true
            [pscustomobject]@{
                Name            = ([string]$p.DisplayName).Trim()
                Version         = $p.DisplayVersion
                Publisher       = $p.Publisher
                InstallDate     = ConvertTo-IsoDate $p.InstallDate
                SizeMB          = if ($p.EstimatedSize) { [math]::Round([double]$p.EstimatedSize / 1024, 1) } else { $null }
                Architecture    = $root.Arch
                Scope           = $root.Scope
                InstallLocation = $p.InstallLocation
            }
        }
    }
    @($items | Sort-Object Name, Version)
}

function Get-HotfixInfo {
    @(Get-Wmi Win32_QuickFixEngineering | ForEach-Object {
            $installed = $null
            try { if ($_.InstalledOn) { $installed = ([datetime]$_.InstalledOn).ToString('yyyy-MM-dd') } } catch { }
            [pscustomobject]@{ HotFixID = $_.HotFixID; Description = $_.Description; InstalledOn = $installed }
        } | Sort-Object InstalledOn -Descending)
}

# ----------------------------------------------------------------------------------
# Running software + live resources (sampled together so CPU figures line up)
# ----------------------------------------------------------------------------------

function Get-PerfSnapshot {
    $cpu = Get-Wmi Win32_PerfRawData_PerfOS_Processor -Filter "Name='_Total'" | Select-Object -First 1
    $procTimes = @{}
    foreach ($p in (Get-Wmi Win32_Process)) { $procTimes[[string]$p.ProcessId] = [double]$p.KernelModeTime + [double]$p.UserModeTime }
    $disk = Get-Wmi Win32_PerfRawData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" | Select-Object -First 1
    $net = @{}
    foreach ($n in (Get-Wmi Win32_PerfRawData_Tcpip_NetworkInterface)) {
        $net[[string]$n.Name] = @{ Rx = [double]$n.BytesReceivedPersec; Tx = [double]$n.BytesSentPersec }
    }
    @{
        Time      = Get-Date
        CpuIdle   = if ($cpu) { [double]$cpu.PercentProcessorTime } else { $null }
        CpuStamp  = if ($cpu) { [double]$cpu.Timestamp_Sys100NS } else { $null }
        ProcTimes = $procTimes
        DiskRead  = if ($disk) { [double]$disk.DiskReadBytesPersec } else { $null }
        DiskWrite = if ($disk) { [double]$disk.DiskWriteBytesPersec } else { $null }
        Net       = $net
    }
}

function Get-RunningState {
    param([int]$SampleSeconds = 5, [int]$TopProcessCount = 15, [switch]$IncludeCommandLine)

    $first = Get-PerfSnapshot
    Start-Sleep -Seconds ([math]::Max(1, $SampleSeconds))
    $second = Get-PerfSnapshot
    $elapsed = [math]::Max(0.5, ($second.Time - $first.Time).TotalSeconds)

    $os = Get-Wmi Win32_OperatingSystem | Select-Object -First 1
    $cs = Get-Wmi Win32_ComputerSystem | Select-Object -First 1
    $logical = 1
    if ($cs -and $cs.NumberOfLogicalProcessors) { $logical = [int]$cs.NumberOfLogicalProcessors }
    elseif ([System.Environment]::ProcessorCount -gt 0) { $logical = [System.Environment]::ProcessorCount }

    # ---- CPU -------------------------------------------------------------------
    $cpuPercent = $null
    if ($null -ne $first.CpuIdle -and $null -ne $second.CpuIdle -and ($second.CpuStamp - $first.CpuStamp) -gt 0) {
        # PercentProcessorTime is an inverse 100ns timer: the raw value counts idle time.
        $cpuPercent = (1 - (($second.CpuIdle - $first.CpuIdle) / ($second.CpuStamp - $first.CpuStamp))) * 100
        $cpuPercent = [math]::Round([math]::Min(100, [math]::Max(0, $cpuPercent)), 1)
    } else {
        $loads = @(Get-Wmi Win32_Processor | ForEach-Object { $_.LoadPercentage } | Where-Object { $null -ne $_ })
        if ($loads.Count) { $cpuPercent = [math]::Round(($loads | Measure-Object -Average).Average, 1) }
    }

    # ---- Processes -------------------------------------------------------------
    $owners = @{}
    try {
        foreach ($gp in (Get-Process -IncludeUserName -ErrorAction Stop)) { $owners[[string]$gp.Id] = $gp.UserName }
    } catch { }

    $rawProcs = @(Get-Wmi Win32_Process)
    $processes = @($rawProcs | ForEach-Object {
            $id = [string]$_.ProcessId
            $now = [double]$_.KernelModeTime + [double]$_.UserModeTime
            $pct = $null
            if ($first.ProcTimes.ContainsKey($id) -and $now -ge $first.ProcTimes[$id]) {
                $pct = [math]::Round((($now - $first.ProcTimes[$id]) / 1e7) / $elapsed / $logical * 100, 1)
            }
            $o = [ordered]@{
                Name        = $_.Name
                PID         = [int]$_.ProcessId
                ParentPID   = [int]$_.ParentProcessId
                User        = $owners[$id]
                CpuPercent  = $pct
                CpuSeconds  = [math]::Round($now / 1e7, 1)
                MemoryMB    = ConvertTo-MB $_.WorkingSetSize
                Threads     = $_.ThreadCount
                Handles     = $_.HandleCount
                SessionId   = $_.SessionId
                StartTime   = ConvertTo-IsoDate $_.CreationDate
                Path        = $_.ExecutablePath
            }
            if ($IncludeCommandLine) { $o.CommandLine = $_.CommandLine }
            [pscustomobject]$o
        } | Sort-Object Name, PID)

    $threadTotal = 0; $handleTotal = 0
    foreach ($p in $processes) { $threadTotal += [int]$p.Threads; $handleTotal += [int]$p.Handles }

    # ---- Services --------------------------------------------------------------
    $services = @(Get-Wmi Win32_Service | Sort-Object DisplayName | ForEach-Object {
            [pscustomobject]@{
                Name        = $_.Name
                DisplayName = $_.DisplayName
                State       = $_.State
                StartMode   = $_.StartMode
                Account     = $_.StartName
                PID         = if ($_.ProcessId) { [int]$_.ProcessId } else { $null }
                Path        = $_.PathName
            }
        })

    # ---- Startup items / listening ports / interactive users --------------------
    $startup = @(Get-Wmi Win32_StartupCommand | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; Command = $_.Command; Location = $_.Location; User = $_.User }
        })

    $procNames = @{}
    foreach ($p in $processes) { $procNames[[string]$p.PID] = $p.Name }
    $listening = @()
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        try {
            $listening = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Sort-Object LocalPort, LocalAddress | ForEach-Object {
                    [pscustomobject]@{ Protocol = 'TCP'; Address = $_.LocalAddress; Port = [int]$_.LocalPort; PID = [int]$_.OwningProcess; Process = $procNames[[string]$_.OwningProcess] }
                })
        } catch { }
    }

    $interactive = @($processes | Where-Object { $_.Name -eq 'explorer.exe' -and $_.User } | ForEach-Object { $_.User } | Sort-Object -Unique)

    # ---- Memory ----------------------------------------------------------------
    $memTotal = $null; $memFree = $null; $commitTotal = $null; $commitFree = $null
    if ($os) {
        $memTotal = [double]$os.TotalVisibleMemorySize * 1KB
        $memFree = [double]$os.FreePhysicalMemory * 1KB
        $commitTotal = [double]$os.TotalVirtualMemorySize * 1KB
        $commitFree = [double]$os.FreeVirtualMemory * 1KB
    }
    $pageFiles = @(Get-Wmi Win32_PageFileUsage | ForEach-Object {
            [pscustomobject]@{ Path = $_.Name; AllocatedMB = $_.AllocatedBaseSize; UsedMB = $_.CurrentUsage; PeakMB = $_.PeakUsage }
        })

    # ---- Disk and network throughput -------------------------------------------
    $diskRead = $null; $diskWrite = $null
    if ($null -ne $first.DiskRead -and $null -ne $second.DiskRead) {
        $diskRead = [math]::Round([math]::Max(0, $second.DiskRead - $first.DiskRead) / $elapsed / 1MB, 2)
        $diskWrite = [math]::Round([math]::Max(0, $second.DiskWrite - $first.DiskWrite) / $elapsed / 1MB, 2)
    }
    $netRates = @(foreach ($name in $second.Net.Keys) {
            if (-not $first.Net.ContainsKey($name)) { continue }
            $rx = [math]::Max(0, $second.Net[$name].Rx - $first.Net[$name].Rx) / $elapsed
            $tx = [math]::Max(0, $second.Net[$name].Tx - $first.Net[$name].Tx) / $elapsed
            [pscustomobject]@{ Interface = $name; ReceiveKbps = [math]::Round($rx * 8 / 1000, 1); SendKbps = [math]::Round($tx * 8 / 1000, 1) }
        })

    $resources = [pscustomobject]@{
        SampleSeconds        = [math]::Round($elapsed, 1)
        CpuPercent           = $cpuPercent
        LogicalProcessors    = $logical
        MemoryTotalGB        = ConvertTo-GB $memTotal
        MemoryUsedGB         = if ($null -ne $memTotal) { ConvertTo-GB ($memTotal - $memFree) } else { $null }
        MemoryFreeGB         = ConvertTo-GB $memFree
        MemoryUsedPercent    = if ($memTotal) { Get-Percent ($memTotal - $memFree) $memTotal } else { $null }
        CommitTotalGB        = ConvertTo-GB $commitTotal
        CommitUsedGB         = if ($null -ne $commitTotal) { ConvertTo-GB ($commitTotal - $commitFree) } else { $null }
        CommitUsedPercent    = if ($commitTotal) { Get-Percent ($commitTotal - $commitFree) $commitTotal } else { $null }
        PageFiles            = $pageFiles
        DiskReadMBps         = $diskRead
        DiskWriteMBps        = $diskWrite
        NetworkThroughput    = $netRates
        ProcessCount         = $processes.Count
        ThreadCount          = $threadTotal
        HandleCount          = $handleTotal
        TopProcessesByCpu    = @($processes | Where-Object { $_.PID -ne 0 } | Sort-Object CpuPercent -Descending | Select-Object -First $TopProcessCount Name, PID, User, CpuPercent, MemoryMB)
        TopProcessesByMemory = @($processes | Sort-Object MemoryMB -Descending | Select-Object -First $TopProcessCount Name, PID, User, MemoryMB, CpuPercent)
    }

    [pscustomobject]@{
        Resources        = $resources
        Processes        = $processes
        Services         = $services
        StartupItems     = $startup
        ListeningPorts   = $listening
        InteractiveUsers = $interactive
    }
}

function Get-HealthWarnings {
    param($Inventory)
    $w = New-Object System.Collections.ArrayList
    $r = $Inventory.Resources
    if ($r) {
        if ($null -ne $r.CpuPercent -and $r.CpuPercent -ge 90) { [void]$w.Add("CPU at $($r.CpuPercent)% during sampling") }
        if ($null -ne $r.MemoryUsedPercent -and $r.MemoryUsedPercent -ge 90) { [void]$w.Add("Memory $($r.MemoryUsedPercent)% used") }
        if ($null -ne $r.CommitUsedPercent -and $r.CommitUsedPercent -ge 90) { [void]$w.Add("Commit charge $($r.CommitUsedPercent)% used") }
    }
    if ($Inventory.Storage) {
        foreach ($v in $Inventory.Storage.Volumes) {
            if ($null -ne $v.FreePercent -and $v.FreePercent -lt 10) { [void]$w.Add("Volume $($v.Drive) only $($v.FreePercent)% free ($($v.FreeGB) GB)") }
        }
        foreach ($d in $Inventory.Storage.PhysicalDisks) {
            if ($d.Health -and $d.Health -ne 'Healthy' -and $d.Health -ne 'Unknown') { [void]$w.Add("Disk $($d.Index) ($($d.Model)) health: $($d.Health)") }
            elseif ($d.SmartStatus -and $d.SmartStatus -ne 'OK') { [void]$w.Add("Disk $($d.Index) ($($d.Model)) status: $($d.SmartStatus)") }
        }
    }
    if ($Inventory.System -and $null -ne $Inventory.System.UptimeDays -and $Inventory.System.UptimeDays -gt 30) {
        [void]$w.Add("Uptime $([math]::Round($Inventory.System.UptimeDays)) days - consider a reboot")
    }
    if ($Inventory.Services) {
        $stopped = @($Inventory.Services | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' })
        if ($stopped.Count -gt 0) { [void]$w.Add("$($stopped.Count) automatic service(s) not running") }
    }
    @($w)
}

# ----------------------------------------------------------------------------------
# Network discovery
# ----------------------------------------------------------------------------------

function Get-LocalIPv4 {
    # One entry per IPv4 address on an enabled adapter.
    $list = New-Object System.Collections.ArrayList
    foreach ($cfg in (Get-Wmi Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE')) {
        $addresses = @($cfg.IPAddress); $subnets = @($cfg.IPSubnet)
        for ($i = 0; $i -lt $addresses.Count; $i++) {
            $ip = $addresses[$i]
            if ($ip -notmatch '^\d+\.\d+\.\d+\.\d+$' -or $ip -like '169.254.*' -or $ip -like '127.*') { continue }
            if ($i -ge $subnets.Count -or $subnets[$i] -notmatch '^\d+\.\d+\.\d+\.\d+$') { continue }
            [void]$list.Add([pscustomobject]@{
                    IP      = $ip
                    Prefix  = ConvertTo-PrefixLength $subnets[$i]
                    Gateway = @($cfg.DefaultIPGateway | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
                    Mac     = Format-Mac $cfg.MACAddress
                })
        }
    }
    @($list)
}

function Get-ScanTargets {
    param([string]$Subnet, [int]$MaxHosts, $LocalAddresses)
    $notes = New-Object System.Collections.ArrayList
    $ranges = New-Object System.Collections.ArrayList

    if ($Subnet) {
        foreach ($cidr in ($Subnet -split '[,;\s]+' | Where-Object { $_ })) {
            if ($cidr -notmatch '^(\d+\.\d+\.\d+\.\d+)(?:/(\d{1,2}))?$') { [void]$notes.Add("Ignored invalid subnet '$cidr'"); continue }
            $prefix = if ($Matches[2]) { [int]$Matches[2] } else { 24 }
            try { [void]$ranges.Add((Get-SubnetRange $Matches[1] $prefix)) } catch { [void]$notes.Add("Ignored invalid subnet '$cidr'") }
        }
    } else {
        $withGateway = @($LocalAddresses | Where-Object { $_.Gateway.Count -gt 0 })
        $use = if ($withGateway.Count) { $withGateway } else { @($LocalAddresses) }
        foreach ($a in $use) {
            $range = Get-SubnetRange $a.IP $a.Prefix
            if ($range.HostCount -gt $MaxHosts) {
                $narrow = Get-SubnetRange $a.IP 24
                [void]$notes.Add("$($range.Cidr) has $($range.HostCount) hosts (cap $MaxHosts); scanned $($narrow.Cidr) only. Use -Subnet / -MaxHostsPerSubnet to widen.")
                $range = $narrow
            }
            [void]$ranges.Add($range)
        }
    }

    $seen = @{}
    $targets = New-Object System.Collections.ArrayList
    $scanned = New-Object System.Collections.ArrayList
    foreach ($range in $ranges) {
        if ($scanned -contains $range.Cidr) { continue }
        [void]$scanned.Add($range.Cidr)
        $last = $range.Last
        if ($range.HostCount -gt $MaxHosts) {
            $last = $range.First + [uint64]$MaxHosts - 1
            [void]$notes.Add("$($range.Cidr) truncated to the first $MaxHosts addresses (raise -MaxHostsPerSubnet to scan it all).")
        }
        for ($n = $range.First; $n -le $last; $n++) {
            $ip = ConvertFrom-IPNumber $n
            if (-not $seen.ContainsKey($ip)) { $seen[$ip] = $true; [void]$targets.Add($ip) }
        }
    }
    [pscustomobject]@{ Targets = @($targets); Ranges = @($ranges); Subnets = @($scanned); Notes = @($notes) }
}

function Invoke-PingSweep {
    param([string[]]$Targets, [int]$TimeoutMs = 750, [int]$BatchSize = 200)
    $alive = @{}
    for ($offset = 0; $offset -lt $Targets.Count; $offset += $BatchSize) {
        $batch = $Targets[$offset..([math]::Min($offset + $BatchSize, $Targets.Count) - 1)]
        $jobs = foreach ($ip in $batch) {
            $pinger = New-Object System.Net.NetworkInformation.Ping
            $task = $null
            try { $task = $pinger.SendPingAsync($ip, $TimeoutMs) } catch { }
            [pscustomobject]@{ IP = $ip; Ping = $pinger; Task = $task }
        }
        $tasks = [System.Threading.Tasks.Task[]]@($jobs | Where-Object { $_.Task } | ForEach-Object { $_.Task })
        if ($tasks.Count) { try { [void][System.Threading.Tasks.Task]::WaitAll($tasks, $TimeoutMs + 3000) } catch { } }
        foreach ($j in $jobs) {
            try {
                if ($j.Task -and $j.Task.Status -eq 'RanToCompletion' -and $j.Task.Result.Status -eq 'Success') {
                    $ttl = $null
                    try { $ttl = $j.Task.Result.Options.Ttl } catch { }
                    $alive[$j.IP] = [pscustomobject]@{ ResponseMs = [int]$j.Task.Result.RoundtripTime; Ttl = $ttl }
                }
            } catch { }
            try { $j.Ping.Dispose() } catch { }
        }
    }
    $alive
}

function Get-ArpTable {
    $table = @{}
    $done = $false
    if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
        try {
            foreach ($n in (Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop)) {
                if ($n.State -eq 'Unreachable' -or $n.State -eq 'Incomplete') { continue }
                $mac = Format-Mac $n.LinkLayerAddress
                if ($mac) { $table[[string]$n.IPAddress] = $mac }
            }
            $done = $true
        } catch { }
    }
    if (-not $done -and (Get-Command arp.exe -ErrorAction SilentlyContinue)) {
        foreach ($line in @(& arp.exe -a 2>$null)) {
            if ($line -match '^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\s') {
                $mac = Format-Mac $Matches[2]
                if ($mac) { $table[$Matches[1]] = $mac }
            }
        }
    }
    # Drop broadcast / multicast entries.
    foreach ($ip in @($table.Keys)) {
        $mac = $table[$ip]
        $firstOctet = [int]($ip -split '\.')[0]
        if ($mac -eq 'FF:FF:FF:FF:FF:FF' -or $mac -eq '00:00:00:00:00:00' -or $mac -like '01:00:5E:*' -or $firstOctet -ge 224) { $table.Remove($ip) }
    }
    $table
}

function Test-TcpPorts {
    # Returns @{ ip = @(open ports) } using non-blocking connects.
    param([string[]]$Hosts, [int[]]$Ports, [int]$TimeoutMs = 600, [int]$BatchSize = 48)
    $open = @{}
    if (-not $Ports -or -not $Hosts) { return $open }
    for ($offset = 0; $offset -lt $Hosts.Count; $offset += $BatchSize) {
        $batch = $Hosts[$offset..([math]::Min($offset + $BatchSize, $Hosts.Count) - 1)]
        $jobs = foreach ($ip in $batch) {
            foreach ($port in $Ports) {
                $client = New-Object System.Net.Sockets.TcpClient
                $task = $null
                try { $task = $client.ConnectAsync($ip, $port) } catch { }
                [pscustomobject]@{ IP = $ip; Port = $port; Client = $client; Task = $task }
            }
        }
        $tasks = [System.Threading.Tasks.Task[]]@($jobs | Where-Object { $_.Task } | ForEach-Object { $_.Task })
        if ($tasks.Count) { try { [void][System.Threading.Tasks.Task]::WaitAll($tasks, $TimeoutMs) } catch { } }
        foreach ($j in $jobs) {
            try {
                if ($j.Task -and $j.Task.Status -eq 'RanToCompletion' -and $j.Client.Connected) {
                    if (-not $open.ContainsKey($j.IP)) { $open[$j.IP] = New-Object System.Collections.ArrayList }
                    [void]$open[$j.IP].Add([int]$j.Port)
                }
            } catch { }
            try { $j.Client.Close() } catch { }
        }
    }
    $open
}

function Resolve-HostNames {
    param([string[]]$Hosts, [int]$TimeoutMs = 4000, [int]$BatchSize = 64)
    $names = @{}
    for ($offset = 0; $offset -lt $Hosts.Count; $offset += $BatchSize) {
        $batch = $Hosts[$offset..([math]::Min($offset + $BatchSize, $Hosts.Count) - 1)]
        $jobs = foreach ($ip in $batch) {
            $task = $null
            try { $task = [System.Net.Dns]::GetHostEntryAsync($ip) } catch { }
            [pscustomobject]@{ IP = $ip; Task = $task }
        }
        $tasks = [System.Threading.Tasks.Task[]]@($jobs | Where-Object { $_.Task } | ForEach-Object { $_.Task })
        if ($tasks.Count) { try { [void][System.Threading.Tasks.Task]::WaitAll($tasks, $TimeoutMs) } catch { } }
        foreach ($j in $jobs) {
            try {
                if ($j.Task -and $j.Task.Status -eq 'RanToCompletion' -and $j.Task.Result.HostName -and $j.Task.Result.HostName -ne $j.IP) {
                    $names[$j.IP] = $j.Task.Result.HostName
                }
            } catch { }
        }
    }
    $names
}

function Import-OuiTable {
    # IEEE oui.csv columns: Registry, Assignment, Organization Name, Organization Address
    param([string]$Path)
    $table = @{}
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $table }
    try {
        foreach ($row in (Import-Csv -LiteralPath $Path)) {
            if ($row.Assignment -and $row.'Organization Name') { $table[$row.Assignment.ToUpper()] = $row.'Organization Name' }
        }
    } catch { [void]$script:Errors.Add("OUI file: $($_.Exception.Message)") }
    $table
}

function Get-DeviceGuess {
    param([int[]]$Ports, $Ttl, [bool]$IsGateway)
    if ($IsGateway) { return 'Router / gateway' }
    if ($Ports -contains 9100 -or $Ports -contains 515 -or $Ports -contains 631) { return 'Printer' }
    if ($Ports -contains 3389 -or $Ports -contains 135) { return 'Windows computer' }
    if ($Ports -contains 445) { return 'Windows computer or NAS (SMB)' }
    if ($Ports -contains 22) { return 'Linux/Unix host or network device (SSH)' }
    if ($Ports -contains 80 -or $Ports -contains 443) { return 'Web-managed device (switch, AP, camera, IoT)' }
    if ($null -ne $Ttl) {
        if ([int]$Ttl -gt 128) { return 'Network device (TTL > 128)' }
        if ([int]$Ttl -le 64) { return 'Linux/Unix, phone or embedded device' }
        return 'Windows computer (firewalled)'
    }
    'Unknown'
}

function Get-NetworkDevices {
    param([string]$Subnet, [int]$MaxHosts, [int]$PingTimeoutMs, [int[]]$Ports, [int]$PortTimeoutMs, [string]$OuiFile)

    $local = @(Get-LocalIPv4)
    $plan = Get-ScanTargets -Subnet $Subnet -MaxHosts $MaxHosts -LocalAddresses $local
    $targets = @($plan.Targets)
    if (-not $targets.Count) {
        return [pscustomobject]@{ Subnets = @(); Notes = @($plan.Notes) + 'No IPv4 subnet found to scan.'; AddressesScanned = 0; Devices = @() }
    }

    $alive = Invoke-PingSweep -Targets $targets -TimeoutMs $PingTimeoutMs
    # Second pass catches hosts that dropped the first echo (sleeping Wi-Fi clients etc.).
    $retry = @($targets | Where-Object { -not $alive.ContainsKey($_) })
    if ($retry.Count) {
        $again = Invoke-PingSweep -Targets $retry -TimeoutMs $PingTimeoutMs
        foreach ($k in $again.Keys) { $alive[$k] = $again[$k] }
    }

    # Hosts that block ICMP still answer ARP on the local segment.
    $arp = Get-ArpTable
    $targetSet = @{}
    foreach ($t in $targets) { $targetSet[$t] = $true }
    $found = @{}
    foreach ($ip in $alive.Keys) { $found[$ip] = $true }
    foreach ($ip in $arp.Keys) { if ($targetSet.ContainsKey($ip)) { $found[$ip] = $true } }

    $localIps = @{}; $gateways = @{}
    foreach ($a in $local) { $localIps[$a.IP] = $a.Mac; foreach ($g in $a.Gateway) { $gateways[$g] = $true } }
    foreach ($ip in $localIps.Keys) { if ($targetSet.ContainsKey($ip)) { $found[$ip] = $true } }

    $hosts = @($found.Keys | Sort-Object { ConvertTo-IPNumber $_ })
    $openPorts = Test-TcpPorts -Hosts $hosts -Ports $Ports -TimeoutMs $PortTimeoutMs
    $names = Resolve-HostNames -Hosts $hosts
    $oui = Import-OuiTable $OuiFile

    $devices = @(foreach ($ip in $hosts) {
            $isLocal = $localIps.ContainsKey($ip)
            $mac = if ($isLocal) { $localIps[$ip] } else { $arp[$ip] }
            $ports = @()
            if ($openPorts.ContainsKey($ip)) { $ports = @($openPorts[$ip] | Sort-Object) }
            $ping = $alive[$ip]
            $vendor = $null
            if ($mac -and $oui.Count) { $vendor = $oui[($mac -replace ':', '').Substring(0, 6)] }
            $name = $names[$ip]
            if ($isLocal -and -not $name) { $name = [System.Environment]::MachineName }
            [pscustomobject]@{
                IPAddress   = $ip
                HostName    = $name
                MacAddress  = $mac
                Vendor      = $vendor
                DeviceGuess = if ($isLocal) { 'This computer' } else { Get-DeviceGuess -Ports $ports -Ttl $(if ($ping) { $ping.Ttl }) -IsGateway $gateways.ContainsKey($ip) }
                RespondsToPing = [bool]$ping
                ResponseMs  = if ($ping) { $ping.ResponseMs } else { $null }
                Ttl         = if ($ping) { $ping.Ttl } else { $null }
                OpenPorts   = $ports
                IsGateway   = $gateways.ContainsKey($ip)
                IsLocalHost = $isLocal
            }
        })

    [pscustomobject]@{
        Subnets          = @($plan.Subnets)
        Notes            = @($plan.Notes)
        AddressesScanned = $targets.Count
        PortsProbed      = @($Ports)
        Devices          = $devices
    }
}

# ----------------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------------

function ConvertTo-SafeHtml {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { $Value = (@($Value) -join ', ') }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-HtmlTable {
    param($Rows, [string[]]$Columns)
    $rows = @($Rows | Where-Object { $null -ne $_ })
    if (-not $rows.Count) { return '<p class="none">None found.</p>' }
    if (-not $Columns) { $Columns = @($rows[0].PSObject.Properties | ForEach-Object { $_.Name }) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="scroll"><table><thead><tr>')
    foreach ($c in $Columns) { [void]$sb.Append('<th>' + (ConvertTo-SafeHtml $c) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) { [void]$sb.Append('<td>' + (ConvertTo-SafeHtml $r.$c) + '</td>') }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    $sb.ToString()
}

function ConvertTo-HtmlFacts {
    # Two-column key/value table from a single object, skipping nested collections.
    param($Object, [string[]]$Properties)
    if (-not $Object) { return '<p class="none">Not available.</p>' }
    if (-not $Properties) { $Properties = @($Object.PSObject.Properties | ForEach-Object { $_.Name }) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table class="facts"><tbody>')
    foreach ($p in $Properties) {
        $v = $Object.$p
        if ($null -eq $v -or "$v" -eq '') { continue }
        [void]$sb.Append('<tr><th>' + (ConvertTo-SafeHtml $p) + '</th><td>' + (ConvertTo-SafeHtml $v) + '</td></tr>')
    }
    [void]$sb.Append('</tbody></table>')
    $sb.ToString()
}

function New-HtmlSection {
    param([string]$Title, [string]$Body, [switch]$Open, $Count)
    $label = ConvertTo-SafeHtml $Title
    if ($null -ne $Count) { $label += ' <span class="count">' + [int]$Count + '</span>' }
    $openAttr = if ($Open) { ' open' } else { '' }
    "<details$openAttr><summary>$label</summary>$Body</details>"
}

function ConvertTo-InventoryHtml {
    param($Inventory)
    $s = $Inventory.System
    $title = if ($s) { $s.ComputerName } else { $Inventory.Meta.ComputerName }
    $parts = New-Object System.Collections.ArrayList

    if ($Inventory.Warnings -and @($Inventory.Warnings).Count) {
        $items = (@($Inventory.Warnings) | ForEach-Object { '<li>' + (ConvertTo-SafeHtml $_) + '</li>' }) -join ''
        [void]$parts.Add("<div class=`"warn`"><strong>Needs attention</strong><ul>$items</ul></div>")
    }

    if ($s) {
        $r = $Inventory.Resources
        $tiles = New-Object System.Collections.ArrayList
        if ($r) {
            if ($null -ne $r.CpuPercent) { [void]$tiles.Add(@('CPU load', "$($r.CpuPercent)%")) }
            if ($null -ne $r.MemoryUsedPercent) { [void]$tiles.Add(@('Memory used', "$($r.MemoryUsedPercent)% of $($r.MemoryTotalGB) GB")) }
            [void]$tiles.Add(@('Processes', "$($r.ProcessCount)"))
        }
        if ($null -ne $s.UptimeDays) { [void]$tiles.Add(@('Uptime', "$($s.UptimeDays) days")) }
        if ($Inventory.Software) { [void]$tiles.Add(@('Installed software', "$(@($Inventory.Software).Count)")) }
        if ($Inventory.NetworkDiscovery) { [void]$tiles.Add(@('Network devices', "$(@($Inventory.NetworkDiscovery.Devices).Count)")) }
        $tileHtml = ($tiles | ForEach-Object { '<div class="tile"><div class="k">' + (ConvertTo-SafeHtml $_[0]) + '</div><div class="v">' + (ConvertTo-SafeHtml $_[1]) + '</div></div>' }) -join ''
        [void]$parts.Add("<div class=`"tiles`">$tileHtml</div>")

        [void]$parts.Add((New-HtmlSection 'System' (ConvertTo-HtmlFacts $s) -Open))
        [void]$parts.Add((New-HtmlSection 'Processors' (ConvertTo-HtmlTable $Inventory.Processors) -Count @($Inventory.Processors).Count))
        if ($Inventory.Memory) {
            $body = (ConvertTo-HtmlFacts $Inventory.Memory @('InstalledGB', 'UsableGB', 'SlotsUsed', 'SlotsTotal', 'MaxCapacityGB')) + (ConvertTo-HtmlTable $Inventory.Memory.Modules)
            [void]$parts.Add((New-HtmlSection 'Memory' $body))
        }
        if ($Inventory.Storage) {
            $body = '<h3>Volumes</h3>' + (ConvertTo-HtmlTable $Inventory.Storage.Volumes) + '<h3>Physical disks</h3>' + (ConvertTo-HtmlTable $Inventory.Storage.PhysicalDisks)
            [void]$parts.Add((New-HtmlSection 'Storage' $body -Open))
        }
        if ($Inventory.Display) {
            $body = '<h3>Video controllers</h3>' + (ConvertTo-HtmlTable $Inventory.Display.VideoControllers) + '<h3>Monitors</h3>' + (ConvertTo-HtmlTable $Inventory.Display.Monitors)
            [void]$parts.Add((New-HtmlSection 'Display' $body))
        }
        [void]$parts.Add((New-HtmlSection 'Network adapters' (ConvertTo-HtmlTable $Inventory.NetworkAdapters) -Count @($Inventory.NetworkAdapters).Count))
        if ($Inventory.Peripherals) {
            $body = '<h3>Printers</h3>' + (ConvertTo-HtmlTable $Inventory.Peripherals.Printers) + '<h3>Batteries</h3>' + (ConvertTo-HtmlTable $Inventory.Peripherals.Batteries)
            [void]$parts.Add((New-HtmlSection 'Peripherals' $body))
        }
        if ($Inventory.Security) {
            $body = (ConvertTo-HtmlFacts $Inventory.Security @('TpmPresent', 'TpmVersion', 'TpmEnabled', 'SecureBoot')) + '<h3>BitLocker</h3>' + (ConvertTo-HtmlTable $Inventory.Security.BitLocker) + '<h3>Antivirus</h3>' + (ConvertTo-HtmlTable $Inventory.Security.Antivirus)
            [void]$parts.Add((New-HtmlSection 'Security' $body))
        }
        if ($r) {
            $body = (ConvertTo-HtmlFacts $r @('SampleSeconds', 'CpuPercent', 'LogicalProcessors', 'MemoryTotalGB', 'MemoryUsedGB', 'MemoryFreeGB', 'MemoryUsedPercent', 'CommitTotalGB', 'CommitUsedGB', 'CommitUsedPercent', 'DiskReadMBps', 'DiskWriteMBps', 'ProcessCount', 'ThreadCount', 'HandleCount'))
            $body += '<h3>Top processes by CPU</h3>' + (ConvertTo-HtmlTable $r.TopProcessesByCpu)
            $body += '<h3>Top processes by memory</h3>' + (ConvertTo-HtmlTable $r.TopProcessesByMemory)
            $body += '<h3>Network throughput</h3>' + (ConvertTo-HtmlTable $r.NetworkThroughput)
            $body += '<h3>Page files</h3>' + (ConvertTo-HtmlTable $r.PageFiles)
            [void]$parts.Add((New-HtmlSection 'System resources' $body -Open))
        }
        [void]$parts.Add((New-HtmlSection 'Running processes' (ConvertTo-HtmlTable $Inventory.Processes) -Count @($Inventory.Processes).Count))
        $running = @($Inventory.Services | Where-Object { $_.State -eq 'Running' })
        [void]$parts.Add((New-HtmlSection 'Running services' (ConvertTo-HtmlTable $running @('DisplayName', 'Name', 'StartMode', 'Account', 'PID', 'Path')) -Count $running.Count))
        $notRunning = @($Inventory.Services | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' })
        if ($notRunning.Count) { [void]$parts.Add((New-HtmlSection 'Automatic services not running' (ConvertTo-HtmlTable $notRunning @('DisplayName', 'Name', 'State', 'Account')) -Count $notRunning.Count)) }
        [void]$parts.Add((New-HtmlSection 'Listening TCP ports' (ConvertTo-HtmlTable $Inventory.ListeningPorts) -Count @($Inventory.ListeningPorts).Count))
        [void]$parts.Add((New-HtmlSection 'Startup items' (ConvertTo-HtmlTable $Inventory.StartupItems) -Count @($Inventory.StartupItems).Count))
        [void]$parts.Add((New-HtmlSection 'Installed software' (ConvertTo-HtmlTable $Inventory.Software @('Name', 'Version', 'Publisher', 'InstallDate', 'SizeMB', 'Architecture', 'Scope')) -Count @($Inventory.Software).Count))
        [void]$parts.Add((New-HtmlSection 'Windows updates (hotfixes)' (ConvertTo-HtmlTable $Inventory.Hotfixes) -Count @($Inventory.Hotfixes).Count))
    }

    if ($Inventory.NetworkDiscovery) {
        $nd = $Inventory.NetworkDiscovery
        $body = '<p>Scanned ' + [int]$nd.AddressesScanned + ' addresses in ' + (ConvertTo-SafeHtml (@($nd.Subnets) -join ', ')) + '.</p>'
        foreach ($n in @($nd.Notes)) { $body += '<p class="note">' + (ConvertTo-SafeHtml $n) + '</p>' }
        $body += ConvertTo-HtmlTable $nd.Devices @('IPAddress', 'HostName', 'MacAddress', 'Vendor', 'DeviceGuess', 'RespondsToPing', 'ResponseMs', 'OpenPorts')
        [void]$parts.Add((New-HtmlSection 'Devices discovered on the network' $body -Open -Count @($nd.Devices).Count))
    }

    if (@($Inventory.Errors).Count) {
        $items = (@($Inventory.Errors) | ForEach-Object { '<li>' + (ConvertTo-SafeHtml $_) + '</li>' }) -join ''
        [void]$parts.Add((New-HtmlSection 'Collection errors' "<ul>$items</ul>" -Count @($Inventory.Errors).Count))
    }

    $css = @'
:root{--bg:#f5f6f8;--card:#fff;--ink:#1c2430;--muted:#5d6978;--line:#dfe3e8;--accent:#0b5cad;--warnbg:#fff4e0;--warnline:#e2a03f}
@media (prefers-color-scheme:dark){:root{--bg:#14181d;--card:#1c2229;--ink:#e6eaef;--muted:#9aa6b4;--line:#2e3742;--accent:#6cb2f5;--warnbg:#3a2c12;--warnline:#b27a25}}
*{box-sizing:border-box}body{margin:0;padding:24px 16px;background:var(--bg);color:var(--ink);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
main{max-width:1200px;margin:0 auto}h1{margin:0 0 2px;font-size:24px}h3{margin:18px 0 6px;font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.sub{color:var(--muted);margin:0 0 18px}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}.tile .k{color:var(--muted);font-size:12px}.tile .v{font-size:17px;font-weight:600}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:10px;padding:0 14px}details[open]{padding-bottom:14px}
summary{cursor:pointer;padding:11px 0;font-weight:600;font-size:15px}.count{font-weight:400;color:var(--muted);font-size:13px;margin-left:6px}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:5px 10px 5px 0;border-bottom:1px solid var(--line);vertical-align:top}
thead th{color:var(--muted);font-weight:600;white-space:nowrap}table.facts{width:auto}table.facts th{color:var(--muted);font-weight:400;padding-right:24px;white-space:nowrap}
td{word-break:break-word}.none,.note{color:var(--muted);margin:6px 0}.warn{background:var(--warnbg);border:1px solid var(--warnline);border-radius:8px;padding:10px 14px;margin-bottom:14px}.warn ul{margin:6px 0 0;padding-left:20px}
'@

    $sub = 'Collected ' + (ConvertTo-SafeHtml $Inventory.Meta.CollectedAt) + ' &middot; scope ' + (ConvertTo-SafeHtml $Inventory.Meta.Scope) + ' &middot; took ' + (ConvertTo-SafeHtml $Inventory.Meta.DurationSeconds) + 's'
    if ($s) { $sub = (ConvertTo-SafeHtml (('{0} {1}' -f $s.Manufacturer, $s.Model).Trim())) + ' &middot; ' + (ConvertTo-SafeHtml $s.OSName) + '<br>' + $sub }

    @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Asset inventory - $(ConvertTo-SafeHtml $title)</title><style>$css</style></head>
<body><main><h1>$(ConvertTo-SafeHtml $title)</h1><p class="sub">$sub</p>
$($parts -join "`n")
</main></body></html>
"@
}

function Export-FlatCsv {
    # Array-valued properties are joined so they survive Export-Csv.
    param($Rows, [string]$Path)
    $rows = @($Rows | Where-Object { $null -ne $_ })
    if (-not $rows.Count) { return }
    $flat = foreach ($r in $rows) {
        $o = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) {
            $v = $p.Value
            if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { $v = (@($v) -join ' ') }
            $o[$p.Name] = $v
        }
        [pscustomobject]$o
    }
    $flat | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

function Write-TextFile {
    param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding $false))
}

# ----------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------

function Invoke-AssetInventory {
    param(
        [string]$Scope = 'Local', [string]$OutputPath, [string]$Subnet, [int]$MaxHostsPerSubnet = 1024,
        [int]$PingTimeoutMs = 750, [string]$ProbePorts = '22,80,135,443,445,3389,9100', [int]$PortTimeoutMs = 600,
        [string]$OuiFile, [int]$SampleSeconds = 5, [int]$TopProcessCount = 15,
        [switch]$IncludeCommandLine, [switch]$NoHtml, [switch]$NoCsv
    )
    $started = Get-Date
    $script:Errors = New-Object System.Collections.ArrayList

    if (-not $OutputPath) {
        $ltsvc = if ($env:windir) { Join-Path $env:windir 'LTSvc' } else { $null }
        if ($ltsvc -and (Test-Path -LiteralPath $ltsvc)) { $OutputPath = Join-Path $ltsvc 'AssetInventory' }
        elseif ($env:ProgramData) { $OutputPath = Join-Path $env:ProgramData 'AssetInventory' }
        else { $OutputPath = Join-Path ([System.IO.Path]::GetTempPath()) 'AssetInventory' }
    }
    if (-not (Test-Path -LiteralPath $OutputPath)) { [void](New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop) }

    $computer = [System.Environment]::MachineName
    $inv = [ordered]@{
        Meta = [ordered]@{
            SchemaVersion   = 1
            ComputerName    = $computer
            Scope           = $Scope
            CollectedAt     = $started.ToString('s')
            CollectedAtUtc  = $started.ToUniversalTime().ToString('s') + 'Z'
            RunAs           = [System.Environment]::UserName
            DurationSeconds = $null
        }
    }

    if ($Scope -ne 'Network') {
        $inv.System = Invoke-Section 'System' { Get-SystemInfo }
        $inv.Processors = @(Invoke-Section 'Processors' { Get-CpuInfo })
        $inv.Memory = Invoke-Section 'Memory' { Get-MemoryInfo }
        $inv.Storage = Invoke-Section 'Storage' { Get-StorageInfo }
        $inv.Display = Invoke-Section 'Display' { Get-DisplayInfo }
        $inv.NetworkAdapters = @(Invoke-Section 'NetworkAdapters' { Get-NetworkAdapterInfo })
        $inv.Peripherals = Invoke-Section 'Peripherals' { Get-PeripheralInfo }
        $inv.Security = Invoke-Section 'Security' { Get-SecurityInfo }
        $inv.Software = @(Invoke-Section 'Software' { Get-InstalledSoftware })
        $inv.Hotfixes = @(Invoke-Section 'Hotfixes' { Get-HotfixInfo })
        $state = Invoke-Section 'RunningState' { Get-RunningState -SampleSeconds $SampleSeconds -TopProcessCount $TopProcessCount -IncludeCommandLine:$IncludeCommandLine }
        if ($state) {
            $inv.Resources = $state.Resources
            $inv.Processes = @($state.Processes)
            $inv.Services = @($state.Services)
            $inv.StartupItems = @($state.StartupItems)
            $inv.ListeningPorts = @($state.ListeningPorts)
            $inv.InteractiveUsers = @($state.InteractiveUsers)
        }
    }

    if ($Scope -ne 'Local') {
        $ports = @($ProbePorts -split '[,;\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ } | Where-Object { $_ -gt 0 -and $_ -lt 65536 })
        $inv.NetworkDiscovery = Invoke-Section 'NetworkDiscovery' {
            Get-NetworkDevices -Subnet $Subnet -MaxHosts $MaxHostsPerSubnet -PingTimeoutMs $PingTimeoutMs -Ports $ports -PortTimeoutMs $PortTimeoutMs -OuiFile $OuiFile
        }
    }

    $inv.Warnings = @(Get-HealthWarnings ([pscustomobject]$inv))
    $inv.Errors = @($script:Errors)
    $inv.Meta.DurationSeconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
    $inventory = [pscustomobject]$inv

    # ---- Write files -------------------------------------------------------------
    $base = Join-Path $OutputPath $computer
    Write-TextFile "${base}_inventory.json" ($inventory | ConvertTo-Json -Depth 8)
    if (-not $NoHtml) { Write-TextFile "${base}_inventory.html" (ConvertTo-InventoryHtml $inventory) }
    if (-not $NoCsv) {
        Export-FlatCsv $inventory.Software "${base}_software.csv"
        Export-FlatCsv $inventory.Processes "${base}_processes.csv"
        Export-FlatCsv $inventory.Services "${base}_services.csv"
        if ($inventory.NetworkDiscovery) { Export-FlatCsv $inventory.NetworkDiscovery.Devices "${base}_network_devices.csv" }
    }

    # ---- Summary for Automate's %shellresult% -----------------------------------
    $out = New-Object System.Collections.ArrayList
    [void]$out.Add("ASSET INVENTORY - $computer - $($inv.Meta.CollectedAt)")
    $s = $inventory.System
    if ($s) {
        [void]$out.Add("Model: $($s.Manufacturer) $($s.Model) | Serial: $($s.SerialNumber) | Chassis: $($s.ChassisType) | Virtual: $($s.IsVirtual)")
        [void]$out.Add("OS: $($s.OSName) $($s.OSVersion) ($($s.OSArchitecture)) | Last boot: $($s.LastBootTime) | Uptime days: $($s.UptimeDays)")
        $cpu = @($inventory.Processors)[0]
        if ($cpu) { [void]$out.Add("CPU: $(@($inventory.Processors).Count) x $($cpu.Name) | $($cpu.Cores) cores / $($cpu.LogicalProcessors) threads") }
        $r = $inventory.Resources
        if ($r) {
            [void]$out.Add("Load: CPU $($r.CpuPercent)% | Memory $($r.MemoryUsedGB)/$($r.MemoryTotalGB) GB ($($r.MemoryUsedPercent)%) | Disk R/W $($r.DiskReadMBps)/$($r.DiskWriteMBps) MB/s")
        }
        if ($inventory.Storage) {
            $vols = @($inventory.Storage.Volumes | ForEach-Object { "$($_.Drive) $($_.FreeGB)/$($_.SizeGB) GB free ($($_.FreePercent)%)" }) -join '; '
            [void]$out.Add("Volumes: $vols")
        }
        $runningServices = @($inventory.Services | Where-Object { $_.State -eq 'Running' }).Count
        [void]$out.Add("Software: $(@($inventory.Software).Count) installed | Processes: $(@($inventory.Processes).Count) | Services running: $runningServices")
    }
    if ($inventory.NetworkDiscovery) {
        $nd = $inventory.NetworkDiscovery
        [void]$out.Add("Network: $(@($nd.Devices).Count) devices found in $(@($nd.Subnets) -join ', ') ($($nd.AddressesScanned) addresses scanned)")
        foreach ($n in @($nd.Notes)) { [void]$out.Add("Note: $n") }
    }
    foreach ($w in @($inventory.Warnings)) { [void]$out.Add("WARNING: $w") }
    foreach ($e in @($inventory.Errors)) { [void]$out.Add("ERROR: $e") }
    [void]$out.Add("Output: $OutputPath")
    [void]$out.Add("Duration: $($inv.Meta.DurationSeconds)s")
    [void]$out.Add('RESULT=SUCCESS')
    $out
}

# Run unless the file is being dot-sourced (tests dot-source it to reach the functions).
if ($MyInvocation.InvocationName -ne '.') {
    # The Automate agent is a 32-bit service. A 32-bit PowerShell on 64-bit Windows sees a
    # redirected registry (missing 64-bit software), so relaunch in the native 64-bit host.
    $native = if ($env:windir) { Join-Path $env:windir 'sysnative\WindowsPowerShell\v1.0\powershell.exe' } else { $null }
    if ($env:PROCESSOR_ARCHITEW6432 -and $PSCommandPath -and $native -and (Test-Path -LiteralPath $native)) {
        $relaunch = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        foreach ($key in $PSBoundParameters.Keys) {
            $value = $PSBoundParameters[$key]
            if ($value -is [switch]) { if ($value.IsPresent) { $relaunch += "-$key" } }
            else { $relaunch += "-$key"; $relaunch += [string]$value }
        }
        & $native @relaunch
        exit $LASTEXITCODE
    }
    try {
        Invoke-AssetInventory @PSBoundParameters
        exit 0
    } catch {
        Write-Output ("RESULT=FAILED: {0}" -f $_.Exception.Message)
        exit 1
    }
}
