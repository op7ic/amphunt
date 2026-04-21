# Hunt: Persistence Mechanism Detection

## Objective
Detect attacker persistence mechanisms including scheduled tasks, registry run keys, service creation, WMI subscriptions, and DLL hijacking.

## Scripts
- **multikeyword_search.py** -- Search for persistence commands
- **hash2processarg.py** -- Detect DLL sideloading by hash

## Important Note
`multikeyword_search.py` performs **plain-text substring matching** -- do NOT use regex patterns (e.g., `.*`) in keyword files. Use the shortest distinctive substring.

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
echo "schtasks /create" > schtask.txt
echo "schtasks /change" >> schtask.txt
echo "at /every" >> schtask.txt
python3 multikeyword_search.py -c config.txt schtask.txt --csv schtask_persistence.csv
```

### Step 3: Service-Based Persistence
```bash
echo "sc create" > service.txt
echo "sc config" >> service.txt
echo "New-Service" >> service.txt
python3 multikeyword_search.py -c config.txt service.txt --csv service_persistence.csv
```

### Step 4: WMI Persistence
```bash
echo "wmic" > wmi.txt
echo "startup" >> wmi.txt
echo "EventSubscription" >> wmi.txt
echo "__EventFilter" >> wmi.txt
echo "CommandLineEventConsumer" >> wmi.txt
python3 multikeyword_search.py -c config.txt wmi.txt --csv wmi_persistence.csv
```

### Step 5: DLL Hijacking
```bash
python3 hash2processarg.py -c config.txt hashset/windows-dll/advpack.dll.txt --csv dll_sideload.csv
python3 hash2processarg.py -c config.txt hashset/windows-dll/comsvcs.dll.txt --csv comsvcs_abuse.csv
```

## MITRE ATT&CK Coverage
- T1053.005 - Scheduled Task, T1543.003 - Windows Service
- T1547.001 - Registry Run Keys, T1546.003 - WMI Event Subscription
- T1574 - DLL Side-Loading

## Follow-Up
- Persistence found -> `instructions/hunt-timeline.md` on affected endpoints
- Tools used -> `instructions/hunt-hashes.md`
- Remote persistence creation -> `instructions/hunt-lateral-movement.md`

## False Positive Guidance
Keywords like `sc create`, `sc config`, `reg add`, and `wmic` appear frequently in legitimate operations. To reduce noise:
- Filter by process parent (focus on cmd.exe/powershell.exe spawned instances, not msiexec/setup.exe)
- Filter by timing (off-hours + unexpected accounts = suspicious)
- Correlate with other hunts (persistence + credential theft = high confidence)
- WMI persistence (`__EventFilter`, `CommandLineEventConsumer`) is almost always worth investigating
