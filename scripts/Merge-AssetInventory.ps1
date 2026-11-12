#requires -Version 3.0
<#
.SYNOPSIS
    Rolls every <COMPUTER>_inventory.json produced by Invoke-AssetInventory.ps1 into
    network-wide CSVs and a single HTML index.

.DESCRIPTION
    Run this on the Automate server (or any workstation that can read the share) against
    the folder the agents uploaded to, for example \\AUTOMATE\LTShare\Uploads\<Client>.
    The folder is searched recursively.

    Output (in -OutputPath):
        all_computers.csv         one row per inventoried computer (hardware + load)
        all_software.csv          one row per computer per installed application
        software_summary.csv      each application/version and how many computers have it
        all_network_devices.csv   every discovered device, de-duplicated, flagged Managed
                                  when it matches a computer that has its own inventory
        inventory_index.html      summary page

.EXAMPLE
    .\Merge-AssetInventory.ps1 -InputPath '\\AUTOMATE\LTShare\Uploads\Contoso' -OutputPath C:\Reports\Contoso
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InputPath,
    [string]$OutputPath
)

if (-not $OutputPath) { $OutputPath = $InputPath }
if (-not (Test-Path -LiteralPath $InputPath)) { throw "Input path not found: $InputPath" }
if (-not (Test-Path -LiteralPath $OutputPath)) { [void](New-Item -ItemType Directory -Path $OutputPath -Force) }

function Encode { param($Value) if ($null -eq $Value) { return '' } [System.Net.WebUtility]::HtmlEncode([string]$Value) }

$files = @(Get-ChildItem -LiteralPath $InputPath -Filter '*_inventory.json' -Recurse -File)
if (-not $files.Count) { throw "No *_inventory.json files found under $InputPath" }

# Keep only the newest file per computer.
$latest = @{}
foreach ($f in $files) {
    try { $inv = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json } catch { Write-Warning "Skipped unreadable file $($f.FullName)"; continue }
    if (-not $inv.Meta) { continue }
    $name = [string]$inv.Meta.ComputerName
    if (-not $latest.ContainsKey($name) -or [datetime]$inv.Meta.CollectedAtUtc -gt [datetime]$latest[$name].Meta.CollectedAtUtc) { $latest[$name] = $inv }
}
$inventories = @($latest.Values | Sort-Object { $_.Meta.ComputerName })

$computers = New-Object System.Collections.ArrayList
$software = New-Object System.Collections.ArrayList
$managedMacs = @{}; $managedIps = @{}; $managedNames = @{}

foreach ($inv in $inventories) {
    $s = $inv.System
    if (-not $s) { continue }
    $managedNames[([string]$s.ComputerName).ToUpper()] = $true
    foreach ($a in @($inv.NetworkAdapters)) {
        if ($a.MacAddress) { $managedMacs[[string]$a.MacAddress] = $s.ComputerName }
        foreach ($ip in @($a.IPv4)) { if ($ip) { $managedIps[[string]$ip] = $s.ComputerName } }
    }
    $cpu = @($inv.Processors) | Select-Object -First 1
    $r = $inv.Resources
    $volumes = @($inv.Storage.Volumes | ForEach-Object { '{0} {1}/{2}GB free' -f $_.Drive, $_.FreeGB, $_.SizeGB }) -join '; '
    $disks = @($inv.Storage.PhysicalDisks | ForEach-Object { '{0} {1}GB {2}' -f $_.Model, $_.SizeGB, $_.MediaType }) -join '; '
    [void]$computers.Add([pscustomobject]@{
            ComputerName      = $s.ComputerName
            Domain            = $s.Domain
            Manufacturer      = $s.Manufacturer
            Model             = $s.Model
            SerialNumber      = $s.SerialNumber
            AssetTag          = $s.AssetTag
            ChassisType       = $s.ChassisType
            IsVirtual         = $s.IsVirtual
            OS                = $s.OSName
            OSVersion         = $s.OSVersion
            OSInstallDate     = $s.OSInstallDate
            BiosVersion       = $s.BiosVersion
            BiosReleaseDate   = $s.BiosReleaseDate
            CPU               = $cpu.Name
            Sockets           = @($inv.Processors).Count
            Cores             = $cpu.Cores
            LogicalProcessors = $cpu.LogicalProcessors
            MemoryGB          = $inv.Memory.InstalledGB
            MemorySlots       = ('{0}/{1}' -f $inv.Memory.SlotsUsed, $inv.Memory.SlotsTotal)
            Disks             = $disks
            Volumes           = $volumes
            IPv4              = (@($inv.NetworkAdapters | ForEach-Object { $_.IPv4 }) -join ' ')
            MacAddresses      = (@($inv.NetworkAdapters | ForEach-Object { $_.MacAddress }) -join ' ')
            LoggedOnUser      = $s.LoggedOnUser
            LastBootTime      = $s.LastBootTime
            UptimeDays        = $s.UptimeDays
            CpuPercent        = $r.CpuPercent
            MemoryUsedPercent = $r.MemoryUsedPercent
            ProcessCount      = $r.ProcessCount
            SoftwareCount     = @($inv.Software).Count
            Warnings          = (@($inv.Warnings) -join ' | ')
            CollectedAt       = $inv.Meta.CollectedAt
        })
    foreach ($app in @($inv.Software)) {
        if (-not $app) { continue }
        [void]$software.Add([pscustomobject]@{ ComputerName = $s.ComputerName; Name = $app.Name; Version = $app.Version; Publisher = $app.Publisher; InstallDate = $app.InstallDate; Scope = $app.Scope })
    }
}

# Discovered devices: de-duplicate on MAC (or IP when no MAC was seen), newest scan wins.
$devices = @{}
foreach ($inv in ($inventories | Sort-Object { [datetime]$_.Meta.CollectedAtUtc })) {
    if (-not $inv.NetworkDiscovery) { continue }
    foreach ($d in @($inv.NetworkDiscovery.Devices)) {
        if (-not $d) { continue }
        $key = if ($d.MacAddress) { [string]$d.MacAddress } else { [string]$d.IPAddress }
        $shortName = if ($d.HostName) { (([string]$d.HostName) -split '\.')[0].ToUpper() } else { $null }
        $managedBy = $null
        if ($d.MacAddress -and $managedMacs.ContainsKey([string]$d.MacAddress)) { $managedBy = $managedMacs[[string]$d.MacAddress] }
        elseif ($managedIps.ContainsKey([string]$d.IPAddress)) { $managedBy = $managedIps[[string]$d.IPAddress] }
        elseif ($shortName -and $managedNames.ContainsKey($shortName)) { $managedBy = $shortName }
        $devices[$key] = [pscustomobject]@{
            IPAddress      = $d.IPAddress
            HostName       = $d.HostName
            MacAddress     = $d.MacAddress
            Vendor         = $d.Vendor
            DeviceGuess    = $d.DeviceGuess
            Managed        = [bool]$managedBy
            InventoriedAs  = $managedBy
            RespondsToPing = $d.RespondsToPing
            OpenPorts      = (@($d.OpenPorts) -join ' ')
            SeenBy         = $inv.Meta.ComputerName
            SeenAt         = $inv.Meta.CollectedAt
        }
    }
}
$deviceList = @($devices.Values | Sort-Object { $v = 0; try { $b = [System.Net.IPAddress]::Parse($_.IPAddress).GetAddressBytes(); $v = ([double]$b[0] * 16777216) + ([double]$b[1] * 65536) + ([double]$b[2] * 256) + $b[3] } catch { }; $v })

$summary = @($software | Group-Object Name, Version | ForEach-Object {
        [pscustomobject]@{ Name = $_.Group[0].Name; Version = $_.Group[0].Version; Publisher = $_.Group[0].Publisher; Computers = $_.Count }
    } | Sort-Object Name, Version)

if ($computers.Count) { $computers | Export-Csv -LiteralPath (Join-Path $OutputPath 'all_computers.csv') -NoTypeInformation -Encoding UTF8 }
if ($software.Count) { $software | Export-Csv -LiteralPath (Join-Path $OutputPath 'all_software.csv') -NoTypeInformation -Encoding UTF8 }
if ($summary.Count) { $summary | Export-Csv -LiteralPath (Join-Path $OutputPath 'software_summary.csv') -NoTypeInformation -Encoding UTF8 }
if ($deviceList.Count) { $deviceList | Export-Csv -LiteralPath (Join-Path $OutputPath 'all_network_devices.csv') -NoTypeInformation -Encoding UTF8 }

function Table {
    param($Rows, [string[]]$Columns)
    $rows = @($Rows)
    if (-not $rows.Count) { return '<p class="none">None.</p>' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="scroll"><table><thead><tr>')
    foreach ($c in $Columns) { [void]$sb.Append('<th>' + (Encode $c) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) { [void]$sb.Append('<td>' + (Encode $r.$c) + '</td>') }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    $sb.ToString()
}

$unmanaged = @($deviceList | Where-Object { -not $_.Managed })
$css = @'
:root{--bg:#f5f6f8;--card:#fff;--ink:#1c2430;--muted:#5d6978;--line:#dfe3e8}
@media (prefers-color-scheme:dark){:root{--bg:#14181d;--card:#1c2229;--ink:#e6eaef;--muted:#9aa6b4;--line:#2e3742}}
body{margin:0;padding:24px 16px;background:var(--bg);color:var(--ink);font:14px/1.45 "Segoe UI",system-ui,sans-serif}main{max-width:1300px;margin:0 auto}
h1{margin:0 0 4px;font-size:24px}h2{font-size:16px;margin:0 0 10px}.sub,.none{color:var(--muted)}section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;margin-top:14px}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:5px 10px 5px 0;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);white-space:nowrap}
'@
$html = @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Network asset inventory</title><style>$css</style></head>
<body><main><h1>Network asset inventory</h1>
<p class="sub">$($computers.Count) inventoried computers &middot; $($deviceList.Count) devices seen on the network &middot; $($unmanaged.Count) without an inventory &middot; generated $(Get-Date -Format 's')</p>
<section><h2>Inventoried computers</h2>$(Table $computers @('ComputerName','Manufacturer','Model','SerialNumber','OS','CPU','MemoryGB','Volumes','IPv4','LoggedOnUser','UptimeDays','CpuPercent','MemoryUsedPercent','Warnings'))</section>
<section><h2>Devices on the network without an inventory</h2>$(Table $unmanaged @('IPAddress','HostName','MacAddress','Vendor','DeviceGuess','OpenPorts','SeenBy'))</section>
<section><h2>All discovered devices</h2>$(Table $deviceList @('IPAddress','HostName','MacAddress','Vendor','DeviceGuess','Managed','InventoriedAs','OpenPorts','SeenBy','SeenAt'))</section>
<section><h2>Software across the network</h2>$(Table $summary @('Name','Version','Publisher','Computers'))</section>
</main></body></html>
"@
[System.IO.File]::WriteAllText((Join-Path $OutputPath 'inventory_index.html'), $html, (New-Object System.Text.UTF8Encoding $false))

"Merged $($computers.Count) computers, $($software.Count) software rows, $($deviceList.Count) network devices ($($unmanaged.Count) unmanaged) into $OutputPath"
