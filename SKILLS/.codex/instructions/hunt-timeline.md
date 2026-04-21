# Hunt: Timeline Analysis

## Objective
Extract and analyze complete event timelines from Cisco Secure Endpoints to understand the full sequence of activity on one or more machines -- file executions, network connections, threat detections, and process activity.

## Scripts
- **timeliner.py** -- Extract timelines for ALL endpoints (one file per host)
- **surround.py** -- Extract timeline for a SINGLE endpoint by connector GUID/UUID

## Commands

### Full Environment Timeline
```bash
python3 timeliner.py -c config.txt -o ./timelines/
python3 timeliner.py -c config.txt -o ./timelines/ --limit 10   # Scoped triage
```

### Single Endpoint Deep-Dive
```bash
python3 surround.py -c config.txt -o ./output/ -u <computer_uuid>
```


## API Limitation
The AMP trajectory API returns a maximum of **500 events per endpoint**. For endpoints with heavy activity, the timeline may be truncated. Correlate with hunt-events for specific event types if needed.

## Post-Extraction Analysis
```bash
grep -A 10 -B 10 -i "cmd\.exe\|rundll32\.exe\|powershell\.exe" timelines/*.txt
grep 'Created by' timelines/*.txt          # Newly created files
grep 'Executed by' timelines/*.txt         # File executions
grep 'Threat' timelines/*.txt              # Threat detections
grep 'NFM' timelines/*.txt                 # Network connections
grep -E '\.doc|\.xls|\.pdf|\.ppt' timelines/*.txt  # Document activity
```

## When to Use
- Initial incident triage
- Building an attack timeline for IR
- Baselining normal endpoint behavior
- Identifying patient-zero

## Follow-Up
- Suspicious hashes found -> `instructions/hunt-hashes.md`
- Anomalous network connections -> `instructions/hunt-network.md`
- Lateral movement suspected -> `instructions/hunt-lateral-movement.md`
