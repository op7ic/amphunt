# Hunt: Network Connection Analysis

## Description
Dump and analyze all network connections and URL requests across endpoints. Use to identify C2 communications, data exfiltration, beaconing patterns, and suspicious outbound connections.

## Scripts
- **allconnections.py** - Dump all TCP/UDP network connections across all endpoints
- **dumpallURL.py** - Extract all URL requests with domain statistics

## Usage

### All Network Connections
```bash
# Dump all connections
python3 allconnections.py -c config.txt

# Export to CSV for analysis
python3 allconnections.py -c config.txt --csv all_connections.csv

# Keep raw IPs (don't sanitize)
python3 allconnections.py -c config.txt --no-sanitize --csv raw_connections.csv

# Limit scope for initial triage
python3 allconnections.py -c config.txt --limit 50 --csv triage_connections.csv
```

### URL Analysis
```bash
# Extract all URLs
python3 dumpallURL.py -c config.txt

# With domain frequency statistics
python3 dumpallURL.py -c config.txt --summary

# Export for external analysis
python3 dumpallURL.py -c config.txt --csv urls.csv --summary
```

## Post-Collection Analysis
```bash
# Find connections to unusual ports
grep -v ':443\|:80\|:53' all_connections.csv

# Find connections to specific IP ranges
grep '192\.168\.' all_connections.csv

# Find high-frequency domains (potential beaconing)
# Review --summary output from dumpallURL.py

# Find connections during off-hours (requires timestamp parsing)
grep -E '0[0-5]:[0-9]{2}:[0-9]{2}' all_connections.csv
```

## When to Use
- Hunting for C2 callback channels
- Detecting data exfiltration
- Identifying beaconing behavior
- Mapping network activity to process execution
- Baseline network behavior analysis

## Follow-Up Skills
- If suspicious IPs found -> `hunt-keywords` to search for those IPs
- If lateral movement ports seen -> `hunt-lateral-movement`
- If URLs link to known malware -> `hunt-hashes` with downloaded file hashes
