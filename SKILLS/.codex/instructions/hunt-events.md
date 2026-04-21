# Hunt: Event Type Extraction

## Objective
Extract all events of a specific type across the environment by Event Type ID. Use for focused investigation of a particular category of security event.

## Scripts
- **getSpecificEvent.py** -- Extract events by Event Type ID to CSV

## Commands
```bash
python3 getSpecificEvent.py -c config.txt <event_type_id> <output.csv>
```

## Event Type Reference

| Event ID | Description | Priority |
|----------|-------------|----------|
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

### Executed Malware
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

## Follow-Up
- Threats found -> `instructions/hunt-timeline.md` on affected endpoints
- Malware executed -> `instructions/hunt-hashes.md` for the SHA256
- Ransomware -> `instructions/hunt-lateral-movement.md` + `instructions/hunt-credentials.md`
