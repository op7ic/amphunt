# Hunt: Network Connection Analysis

## Objective
Dump and analyze all network connections and URL requests across endpoints. Identify C2 communications, data exfiltration, beaconing patterns, and suspicious outbound connections.

## Scripts
- **allconnections.py** -- Dump all TCP/UDP network connections
- **dumpallURL.py** -- Extract all URL requests with domain statistics

## Commands

### All Network Connections
```bash
python3 allconnections.py -c config.txt --csv all_connections.csv
python3 allconnections.py -c config.txt --no-sanitize --csv raw_connections.csv
python3 allconnections.py -c config.txt --limit 50 --csv triage_connections.csv
```

### URL Analysis
```bash
python3 dumpallURL.py -c config.txt --csv urls.csv --summary
```

## Post-Collection Analysis
```bash
grep -v ':443\|:80\|:53' all_connections.csv          # Unusual ports
grep '192\.168\.' all_connections.csv                   # Internal ranges
grep -E '0[0-5]:[0-9]{2}:[0-9]{2}' all_connections.csv # Off-hours activity
```

## When to Use
- Hunting for C2 callbacks
- Detecting data exfiltration
- Identifying beaconing behavior
- Baseline network behavior analysis

## Follow-Up
- Suspicious IPs found -> `instructions/hunt-keywords.md`
- Lateral movement ports -> `instructions/hunt-lateral-movement.md`
- Malware downloads -> `instructions/hunt-hashes.md`
