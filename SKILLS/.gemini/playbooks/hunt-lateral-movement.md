# Playbook: Lateral Movement Detection

## Objective
Detect potential lateral movement via SMB, RDP, WinRM, and RPC/WMIC protocols.

## Scripts
- **lateral_movement.py** -- Detect lateral movement on key ports

## Monitored Ports
| Port(s) | Protocol | Technique |
|---------|----------|-----------|
| 139, 445 | SMB | File shares, PsExec, admin shares |
| 3389 | RDP | Remote Desktop |
| 5985, 5986 | WinRM | PowerShell Remoting |
| 135 | RPC | WMIC, DCOM, scheduled tasks |

## Commands
```bash
python3 lateral_movement.py -c config.txt --csv lateral.csv --summary
python3 lateral_movement.py -c config.txt --limit 100 --csv lateral_triage.csv
```

## Composite Hunts
```bash
python3 hash2connection.py -c config.txt hashset/psexec/psexec.exe.txt --csv psexec_net.csv

echo "psexesvc" > lat_keywords.txt
echo "paexec" >> lat_keywords.txt
echo "winexesvc" >> lat_keywords.txt
echo "ADMIN$" >> lat_keywords.txt
echo "IPC$" >> lat_keywords.txt
python3 multikeyword_search.py -c config.txt lat_keywords.txt --csv lat_kw.csv
```

## MITRE ATT&CK Coverage
- T1021.001 - RDP, T1021.002 - SMB/Admin Shares
- T1021.006 - WinRM, T1570 - Lateral Tool Transfer

## Follow-Up Playbooks
- Source endpoints -> `playbooks/hunt-timeline.md`
- Tools detected -> `playbooks/hunt-hashes.md`
- Credentials compromised -> `playbooks/hunt-credentials.md`
