# Hunt: Persistence Mechanism Detection

## Description
Detect attacker persistence mechanisms including scheduled tasks, registry run keys, service creation, WMI subscriptions, and startup folder modifications. This is a composite hunt using keyword searches for persistence-related commands.

## Scripts
- **multikeyword_search.py** - Search for persistence commands across endpoints
- **hash2processarg.py** - Detect DLL side-loading by hash

## Important Note
`multikeyword_search.py` performs **plain-text substring matching** against AMP activity records. Do NOT use regex patterns (e.g., `.*`) in keyword files -- they will be searched literally and will not match. Use the shortest distinctive substring that identifies the technique.

## Execution Plan

### Step 1: Registry Persistence
```bash
echo "CurrentVersion\Run" > persistence.txt
echo "CurrentVersion\RunOnce" >> persistence.txt
echo "Winlogon" >> persistence.txt
echo "Explorer\Run" >> persistence.txt
echo "reg add" >> persistence.txt
python3 multikeyword_search.py -c config.txt persistence.txt --csv registry_persistence.csv
```

### Step 2: Scheduled Tasks
```bash
echo "schtasks /create" > schtask_persist.txt
echo "schtasks /change" >> schtask_persist.txt
echo "at /every" >> schtask_persist.txt
python3 multikeyword_search.py -c config.txt schtask_persist.txt --csv schtask_persistence.csv
```

### Step 3: Service-Based Persistence
```bash
echo "sc create" > service_persist.txt
echo "sc config" >> service_persist.txt
echo "New-Service" >> service_persist.txt
python3 multikeyword_search.py -c config.txt service_persist.txt --csv service_persistence.csv
```

### Step 4: WMI Persistence
```bash
echo "wmic" > wmi_persist.txt
echo "startup" >> wmi_persist.txt
echo "EventSubscription" >> wmi_persist.txt
echo "__EventFilter" >> wmi_persist.txt
echo "CommandLineEventConsumer" >> wmi_persist.txt
python3 multikeyword_search.py -c config.txt wmi_persist.txt --csv wmi_persistence.csv
```

### Step 5: DLL Hijacking / Side-Loading
```bash
python3 hash2processarg.py -c config.txt hashset/windows-dll/advpack.dll.txt --csv dll_sideload.csv
python3 hash2processarg.py -c config.txt hashset/windows-dll/comsvcs.dll.txt --csv comsvcs_abuse.csv
```

## MITRE ATT&CK Coverage
- T1053.005 - Scheduled Task
- T1543.003 - Windows Service
- T1547.001 - Registry Run Keys
- T1546.003 - WMI Event Subscription
- T1574 - Hijack Execution Flow (DLL Side-Loading)

## When to Use
- Post-incident persistence mechanism sweep
- Proactive hunting for backdoors
- Detecting unauthorized scheduled tasks or services
- Identifying registry modification for persistence
- Validating remediation (confirming persistence removed)

## Follow-Up Skills
- If persistence found -> `hunt-timeline` on affected endpoints
- If tools used to set persistence -> `hunt-hashes` for those tools
- If remote persistence creation -> `hunt-lateral-movement`

## False Positive Guidance
Keywords like `sc create`, `sc config`, `reg add`, and `wmic` appear frequently in legitimate software installations and system administration. To reduce noise:
- **Filter by process parent**: Legitimate `sc create` often runs under installer contexts (msiexec.exe, setup.exe). Focus on instances spawned by cmd.exe, powershell.exe, or unknown parents.
- **Filter by timing**: Persistence set during business hours by IT admin accounts is likely benign. Focus on off-hours or from unexpected user accounts.
- **Correlate with other hunts**: A single `schtasks /create` is unremarkable. Combined with credential tool detection (hunt-credentials) or lateral movement, it becomes high-confidence.
- **WMI persistence is rare in legitimate use**: `__EventFilter` and `CommandLineEventConsumer` matches are almost always worth investigating.
