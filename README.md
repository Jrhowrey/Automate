# ConnectWise Automate asset inventory

Inventories every asset on a network through the Automate agents:

- **Hardware** – make, model, serial, asset tag, BIOS, chassis, CPU, memory modules and
  free slots, physical disks (type, bus, health), volumes, GPUs, monitors, network
  adapters, printers, batteries, TPM / Secure Boot / BitLocker / antivirus.
- **Software** – installed applications (machine-wide and per-user), Windows hotfixes.
- **Running software** – processes (CPU %, memory, owner, path), services, startup items,
  listening TCP ports, interactive users.
- **System resources** – sampled CPU load, memory and commit usage, page files, disk and
  network throughput, top processes by CPU and memory, plus health warnings.
- **Network discovery** – every device answering on the subnet (IP, hostname, MAC,
  open ports, best guess at device type), so printers, switches and unmanaged machines
  show up too.

| File | Purpose |
| --- | --- |
| `scripts/Invoke-AssetInventory.ps1` | Runs on each agent. Read-only. |
| `scripts/Merge-AssetInventory.ps1` | Rolls all agents' results into network-wide CSVs and one HTML page. |

Requires Windows PowerShell 3.0 or later on the agent (Windows 8 / Server 2012 and up
out of the box; Windows 7 / 2008 R2 need WMF 3+).

## How it covers "all assets"

| Scope | What it does | Where to run it |
| --- | --- | --- |
| `Local` (default) | Full detail for the computer it runs on | Every agent |
| `Full` | Local detail **and** a discovery sweep of the local subnet(s) | One agent per site / VLAN |
| `Network` | Discovery sweep only | One agent per site / VLAN |

Agents give the deep detail; the discovery sweep finds everything else. The merge script
then marks each discovered device as managed (it has its own inventory) or not.

## Build the Automate script

Automate scripts are assembled in the Control Center script editor, so this is a
step list rather than an importable file. Function names are as they appear in current
Automate versions; yours may be worded slightly differently.

1. Copy `Invoke-AssetInventory.ps1` to `LTShare\Transfer\Scripts\` on the Automate server.
2. **Automation > Scripts > View Scripts**, create a script named `Asset Inventory`
   (target: Computer).
3. On the **Globals and Parameters** tab add a parameter `Scope` with default `Local`.
4. Add these steps in the **Then** section:

| # | Function | Settings |
| --- | --- | --- |
| 1 | File Download (Forced) | Local file: `Scripts\Invoke-AssetInventory.ps1` – Destination: `%windir%\LTSvc\AssetInventory\Invoke-AssetInventory.ps1` |
| 2 | Shell | Command below |
| 3 | Script Log Message | `%shellresult%` |
| 4 | IF Variable Check | `%shellresult%` **Not Contains** `RESULT=SUCCESS` → jump to `:Failed` |
| 5 | File Upload | `%windir%\LTSvc\AssetInventory\%computername%_inventory.json` |
| 6 | File Upload | `%windir%\LTSvc\AssetInventory\%computername%_inventory.html` |
| 7 | File Upload (optional) | `..._software.csv`, `..._processes.csv`, `..._services.csv`, `..._network_devices.csv` |
| 8 | Script Exit | |
| 9 | Script Note | `:Failed` |
| 10 | Script Exit with Error | `Asset inventory failed: %shellresult%` |

Shell command for step 2:

```
"%windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%windir%\LTSvc\AssetInventory\Invoke-AssetInventory.ps1" -Scope @Scope@
```

`sysnative` makes the 32-bit Automate agent start 64-bit PowerShell. On 32-bit Windows
that path does not exist; use `System32` there. (If the script does start in 32-bit
PowerShell on a 64-bit machine it relaunches itself in 64-bit.)

Uploaded files land under `LTShare\Uploads\` in the client / computer folder.

**Alternative without the file download:** use the **Execute Script** function, type
PowerShell, paste the whole script in, and put `-Scope @Scope@` in the parameters box.

### Running it

- **Every machine:** schedule the script against a group or search with `Scope = Local`
  (weekly is typical).
- **Network sweep:** run it on one always-on agent per site with `Scope = Full`.
- Optional: add an **Extra Data Field Set Value** step to store `%shellresult%` in a
  computer EDF so the summary is visible on the computer screen.

## Network-wide roll-up

On the Automate server, or anywhere that can read the share:

```powershell
.\Merge-AssetInventory.ps1 -InputPath '\\AUTOMATE\LTShare\Uploads\ClientName' -OutputPath 'C:\Reports\ClientName'
```

| Output | Contents |
| --- | --- |
| `all_computers.csv` | One row per computer: model, serial, OS, CPU, memory, disks, IPs, load, warnings |
| `all_software.csv` | One row per computer per application |
| `software_summary.csv` | Each application / version and how many computers have it |
| `all_network_devices.csv` | Every discovered device, de-duplicated, with a `Managed` flag |
| `inventory_index.html` | Summary page, including devices that have no inventory |

## Parameters

| Parameter | Default | Notes |
| --- | --- | --- |
| `-Scope` | `Local` | `Local`, `Network` or `Full` |
| `-OutputPath` | `%windir%\LTSvc\AssetInventory` | Falls back to `%ProgramData%\AssetInventory` when there is no agent folder |
| `-Subnet` | auto-detected | Comma-separated CIDRs, e.g. `"10.0.20.0/24,10.0.30.0/24"` |
| `-MaxHostsPerSubnet` | `1024` | Larger subnets are narrowed to the /24 around the agent |
| `-ProbePorts` | `22,80,135,443,445,3389,9100` | TCP ports used to guess the device type |
| `-PingTimeoutMs` / `-PortTimeoutMs` | `750` / `600` | Raise on slow or Wi-Fi-heavy networks |
| `-OuiFile` | none | Path to IEEE `oui.csv` to fill in the MAC vendor column |
| `-SampleSeconds` | `5` | Length of the CPU / disk / network sample |
| `-TopProcessCount` | `15` | Rows in the top-process tables |
| `-IncludeCommandLine` | off | Adds process command lines, which can contain passwords |
| `-NoHtml`, `-NoCsv` | off | Skip those outputs (JSON is always written) |

## Things to know

- **Discovery is active scanning.** It pings each address and tries a few TCP ports. Run
  it only on networks you manage; IDS/EDR products may log it as a port scan.
- **MAC addresses and ARP-only hosts** are only visible on the agent's own subnet. For
  routed subnets given with `-Subnet` you get IP, hostname and ports, but no MAC, and
  devices that block ping are missed.
- **Device type is a guess** from open ports and TTL. Treat it as a hint.
- **Antivirus** comes from Windows Security Center, which does not exist on servers.
- **Installed software** is read from the registry uninstall keys. Per-user installs are
  only seen for users whose profile is loaded when the script runs. Store (Appx) apps
  are not listed.
- **GPU memory** above 4 GB is under-reported by Windows' own WMI field.
- A section that fails is listed under `Errors` in the output; the rest still completes.
