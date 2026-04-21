# Hunt: Event Type Extraction

## Description
Extract all events of a specific type across the environment by Event Type ID. Use when you need to focus on a particular category of security event such as threats detected, malware executed, ransomware alerts, or cloud IOCs.

## Scripts
- **getSpecificEvent.py** - Extract events by Event Type ID to CSV

## Usage
```bash
python3 getSpecificEvent.py -c config.txt <event_type_id> <output.csv>
```

## Event Type Reference

| Event ID | Description | Priority |
|---|---|---|
| 1090519054 | Threat Detected | HIGH |
| 553648143 | Threat Quarantined | MEDIUM |
| 1107296272 | Executed Malware | CRITICAL |
| 1107296274 | Cloud IOC | HIGH |
| 1107296279 | Vulnerable Application Detected | MEDIUM |
| 1107296284 | Potential Ransomware | CRITICAL |
| 553648147 | Network File Move (NFM) | LOW |

## Common Workflows

### Ransomware Triage
```bash
python3 getSpecificEvent.py -c config.txt 1107296284 ransomware_alerts.csv
```

### All Threat Detections
```bash
python3 getSpecificEvent.py -c config.txt 1090519054 threats.csv
```

### Executed Malware (Critical)
```bash
python3 getSpecificEvent.py -c config.txt 1107296272 executed_malware.csv
```

### Cloud IOC Matches
```bash
python3 getSpecificEvent.py -c config.txt 1107296274 cloud_ioc.csv
```

### Vulnerability Inventory
```bash
python3 getSpecificEvent.py -c config.txt 1107296279 vulnerable_apps.csv
```

## When to Use
- Focused extraction of a specific event category
- Building event-type-specific reports
- Feeding specific event data into external SIEM/SOAR
- Ransomware-specific investigations
- Cloud IOC correlation

## Follow-Up Skills
- If threats found -> `hunt-timeline` on affected endpoints
- If malware executed -> `hunt-hashes` for the malware SHA256
- If ransomware -> `hunt-lateral-movement` + `hunt-credentials` immediately
