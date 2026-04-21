# Hunt: Timeline Analysis

## Description
Extract and analyze complete event timelines from Cisco Secure Endpoints. Use this skill when an analyst needs to understand the full sequence of events on one or more endpoints - file executions, network connections, threat detections, and process activity.

## Scripts
- **timeliner.py** - Extract timelines for ALL endpoints (writes one file per endpoint)
- **surround.py** - Extract timeline for a SINGLE endpoint by its connector GUID/UUID

## Usage

### Full Environment Timeline
```bash
# Extract timelines for all endpoints
python3 timeliner.py -c config.txt -o ./timelines/

# Limit to N endpoints for initial triage
python3 timeliner.py -c config.txt -o ./timelines/ --limit 10
```

### Single Endpoint Deep-Dive
```bash
# Investigate a specific endpoint by UUID
python3 surround.py -c config.txt -o ./output/ -u <computer_uuid>
```

## API Limitation
The AMP trajectory API returns a maximum of **500 events per endpoint**. For endpoints with heavy activity, the timeline may be truncated. If you suspect missing events, correlate with `hunt-events` for specific event types or check the AMP console directly.

## Post-Extraction Analysis
After generating timeline files, search for indicators:
```bash
# Suspicious process execution
grep -A 10 -B 10 -i "cmd\.exe\|rundll32\.exe\|powershell\.exe" timelines/*.txt

# Newly created files
grep 'Created by' timelines/*.txt

# File executions
grep 'Executed by' timelines/*.txt

# Threat detections
grep 'Threat' timelines/*.txt

# Network connections
grep 'NFM' timelines/*.txt

# Document activity (potential data staging)
grep -E '\.doc|\.xls|\.pdf|\.ppt' timelines/*.txt
```

## When to Use
- Initial incident triage
- "What happened on this machine?"
- Building an attack timeline for IR
- Baselining normal endpoint behavior
- Identifying the first-seen or patient-zero endpoint

## Follow-Up Skills
- If suspicious hashes found -> `hunt-hashes`
- If network connections look anomalous -> `hunt-network`
- If lateral movement suspected -> `hunt-lateral-movement`
