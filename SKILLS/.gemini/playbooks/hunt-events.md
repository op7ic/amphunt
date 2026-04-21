# Playbook: Event Type Extraction

## Objective
Extract all events of a specific type by Event Type ID for focused investigation.

## Scripts
- **getSpecificEvent.py** -- Extract events by type ID to CSV

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
```bash
python3 getSpecificEvent.py -c config.txt 1107296284 ransomware.csv    # Ransomware
python3 getSpecificEvent.py -c config.txt 1090519054 threats.csv       # All threats
python3 getSpecificEvent.py -c config.txt 1107296272 malware.csv       # Executed malware
python3 getSpecificEvent.py -c config.txt 1107296274 cloud_ioc.csv     # Cloud IOC
python3 getSpecificEvent.py -c config.txt 1107296279 vulns.csv         # Vulnerabilities
```

## Follow-Up Playbooks
- Threats -> `playbooks/hunt-timeline.md` on affected endpoints
- Malware -> `playbooks/hunt-hashes.md` for the SHA256
- Ransomware -> `playbooks/hunt-lateral-movement.md` + `playbooks/hunt-credentials.md`
