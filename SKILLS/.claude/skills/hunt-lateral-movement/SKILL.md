# Hunt: Lateral Movement Detection

## Description
Detect potential lateral movement by monitoring connections on protocols commonly used for remote execution and file sharing. Monitors SMB, RDP, WinRM, and RPC/WMIC traffic between internal endpoints.

## Scripts
- **lateral_movement.py** - Detect lateral movement across SMB/RDP/WinRM/RPC ports

## Monitored Ports
| Port(s) | Protocol | Technique |
|---|---|---|
| 139, 445 | SMB | File shares, PsExec, admin shares |
| 3389 | RDP | Remote Desktop |
| 5985, 5986 | WinRM | PowerShell Remoting, WinRS |
| 135 | RPC | WMIC, DCOM, scheduled tasks |

## Usage
```bash
# Basic lateral movement scan
python3 lateral_movement.py -c config.txt

# With CSV export and summary statistics
python3 lateral_movement.py -c config.txt --csv lateral_movement.csv --summary

# Limit scope
python3 lateral_movement.py -c config.txt --limit 100 --csv lateral.csv
```

## Composite Hunts
Combine with other tools for deeper investigation:
```bash
# Check for PsExec usage alongside lateral movement
python3 hash2connection.py -c config.txt hashset/psexec/psexec.exe.txt --csv psexec_connections.csv

# Search for remote service creation keywords
echo "psexesvc" > lat_keywords.txt
echo "paexec" >> lat_keywords.txt
echo "winexesvc" >> lat_keywords.txt
echo "ADMIN$" >> lat_keywords.txt
python3 multikeyword_search.py -c config.txt lat_keywords.txt --csv lat_keyword_results.csv
```

## MITRE ATT&CK Coverage
- T1021.001 - Remote Desktop Protocol
- T1021.002 - SMB/Windows Admin Shares
- T1021.003 - DCOM
- T1021.006 - Windows Remote Management
- T1570 - Lateral Tool Transfer

## When to Use
- Active incident response where attacker movement is suspected
- Proactive hunting for unauthorized remote access
- Detecting PsExec/WMI-based lateral movement
- Identifying RDP pivoting between systems
- Mapping attacker path through the environment

## Follow-Up Skills
- If source endpoints identified -> `hunt-timeline` on those specific UUIDs
- If PsExec or tooling detected -> `hunt-hashes` for those tools
- If credentials may be compromised -> `hunt-credentials`
