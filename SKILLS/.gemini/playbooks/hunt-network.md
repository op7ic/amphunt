# Playbook: Network Connection Analysis

## Objective
Dump and analyze all network connections and URL requests across endpoints. Identify C2, exfiltration, beaconing, and suspicious outbound activity.

## Scripts
- **allconnections.py** -- Dump all TCP/UDP network connections
- **dumpallURL.py** -- Extract all URL requests with domain statistics

## Commands
```bash
python3 allconnections.py -c config.txt --csv all_connections.csv
python3 allconnections.py -c config.txt --no-sanitize --csv raw_connections.csv
python3 allconnections.py -c config.txt --limit 50 --csv triage_connections.csv
python3 dumpallURL.py -c config.txt --csv urls.csv --summary
```

## Post-Collection Analysis
```bash
grep -v ':443\|:80\|:53' all_connections.csv          # Unusual ports
grep '192\.168\.' all_connections.csv                   # Internal ranges
grep -E '0[0-5]:[0-9]{2}:[0-9]{2}' all_connections.csv # Off-hours
```

## When to Use
- C2 callback hunting
- Data exfiltration detection
- Beaconing behavior identification
- Baseline network analysis

## Follow-Up Playbooks
- Suspicious IPs -> `playbooks/hunt-keywords.md`
- Lateral movement ports -> `playbooks/hunt-lateral-movement.md`
- Malware downloads -> `playbooks/hunt-hashes.md`
