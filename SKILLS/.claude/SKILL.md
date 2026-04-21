# amphunt - Cisco Secure Endpoint Threat Hunting Skills for Claude

## Purpose
You are a threat hunting assistant operating on the **amphunt** repository - an advanced threat hunting framework for the Cisco Secure Endpoint (AMP) API. Your role is to help security analysts perform endpoint threat hunts by invoking the correct scripts with proper arguments.

## Repository Layout
```
amphunt/
  ├── timeliner.py              # Full endpoint timeline extraction
  ├── surround.py               # Single-endpoint timeline by UUID
  ├── hash2processarg.py        # SHA256 hash to process + command-line args
  ├── hash2connection.py        # SHA256 hash to network connections
  ├── allconnections.py         # Dump all network connections
  ├── dumpallURL.py             # Extract all URL requests
  ├── lateral_movement.py       # Detect lateral movement (SMB/RDP/WinRM/RPC)
  ├── multikeyword_search.py    # Multi-keyword/IOC search across endpoints
  ├── fresh_vulnerabilities.py  # Vulnerable applications + CVE details
  ├── amp_generic_stats.py      # Statistical anomaly detection
  ├── getSpecificEvent.py       # Extract events by Event Type ID
  ├── config.txt                # API credentials (client_id, api_key, region)
  ├── hashset/                  # 134 pre-computed SHA256 hash files
  │   ├── windows-binaries/     # 80 LOLBIN hash sets
  │   ├── hacking-tools/        # 25 offensive tool hash sets
  │   ├── exploits/             # 5 exploit hash sets
  │   ├── psexec/               # PsExec variants
  │   ├── windows-dll/          # 11 DLL hash sets
  │   ├── sysinternals/         # Sysinternals tools
  │   ├── putty_plink/          # SSH tools
  │   ├── teamviewer/           # Remote access
  │   └── msoffice/             # Office binaries
  └── keywordfiles/             # 125 keyword/IOC files for hunt queries
```

## Prerequisites
Before running any hunt, ensure:
1. **Config file exists**: `config.txt` with valid `client_id`, `api_key`, and `region` (nam/eu/apjc)
2. **Library installed**: `pip install -e .` from the repo root
3. **Python 3.6+** available

If `config.txt` is missing or empty, prompt the user to provide credentials before proceeding.


## Working Directory
All commands assume you are running from the **amphunt repository root** (the directory containing `config.txt` and the Python scripts). If you run from a subdirectory, commands will fail with `FileNotFoundError`. On Windows, use `python` instead of `python3` if the latter is not recognized.

## Quick Start: Your First Hunt
```bash
# 1. Verify setup
python3 amp_generic_stats.py -c config.txt --csv stats.csv

# 2. Hunt for credential dumping tools
python3 hash2processarg.py -c config.txt hashset/hacking-tools/mimikatz.txt --csv mimikatz_hunt.csv

# 3. Check for lateral movement
python3 lateral_movement.py -c config.txt --csv lateral.csv --summary
```
If any of these produce hits, read the corresponding sub-skill for deeper investigation steps.

## Available Hunting Sub-Skills

Each sub-skill folder contains a dedicated SKILL.md. Use the appropriate one based on the analyst's request:

| Hunt Scenario | Sub-Skill | Primary Script(s) |
|---|---|---|
| Full timeline extraction | `hunt-timeline` | timeliner.py, surround.py |
| Hash-based IOC hunting | `hunt-hashes` | hash2processarg.py, hash2connection.py |
| Network connection analysis | `hunt-network` | allconnections.py, dumpallURL.py |
| Lateral movement detection | `hunt-lateral-movement` | lateral_movement.py |
| Vulnerability assessment | `hunt-vulnerabilities` | fresh_vulnerabilities.py |
| Keyword/IOC search | `hunt-keywords` | multikeyword_search.py |
| Credential theft detection | `hunt-credentials` | hash2processarg.py + mimikatz/lazagne hashsets |
| Persistence mechanism hunt | `hunt-persistence` | multikeyword_search.py + persistence keywords |
| Statistical anomaly detection | `hunt-stats` | amp_generic_stats.py |
| Event type extraction | `hunt-events` | getSpecificEvent.py |

## Invocation Pattern

All scripts follow this general pattern:
```bash
python3 <script>.py -c config.txt [script-specific-args] [--csv output.csv]
```

## Workflow
1. **Clarify the hunt objective** - What is the analyst looking for?
2. **Select the right sub-skill** - Match the objective to a hunt scenario
3. **Verify config** - Ensure config.txt has credentials
4. **Execute the hunt** - Run the script with correct arguments
5. **Analyze results** - Parse output, highlight findings, suggest follow-up hunts
6. **Chain hunts** - If initial results are interesting, recommend follow-up with a different skill

## Common Event Type IDs
- `1090519054` - Threat Detected
- `553648143` - Threat Quarantined
- `1107296272` - Executed malware
- `1107296274` - Cloud IOC
- `1107296279` - Vulnerable Application Detected
- `1107296284` - Potential Ransomware
- `553648147` - Network File Move (NFM)

## Important Notes
- AMP trajectory API returns max 500 events per endpoint
- Always use `--csv` for large datasets to preserve output
- Use `--limit N` for initial testing before full-environment scans
- Rate limiting is handled automatically by the amp_client library
- When combining hashsets, concatenate files: `cat hashset/a.txt hashset/b.txt > combined.txt`

## Error Handling

If a script fails, diagnose using this checklist:

| Error | Cause | Fix |
|-------|-------|-----|
| `Authentication failed` | Invalid client_id or api_key in config.txt | Verify credentials at https://console.amp.cisco.com |
| `Rate limit exceeded` | Too many API calls | The library auto-retries; if persistent, add `--limit` to reduce scope |
| `Connection refused` / timeout | Wrong region or network issue | Verify `region` in config.txt matches your AMP console (nam/eu/apjc) |
| Empty output (no results) | No matches found OR scope too narrow | Expand search: remove `--limit`, try broader hashset or keyword file |
| `FileNotFoundError` on hashset | Wrong path to hash/keyword file | Verify path relative to repo root: `ls hashset/hacking-tools/` |
| `ModuleNotFoundError: amp_client` | Library not installed | Run `pip install -e .` from the repo root |

## Understanding Output

### hash2processarg.py output
Each line shows: timestamp, hostname, process SHA256, child SHA256, process name, and command-line arguments. A **hit** means an endpoint executed a file whose SHA256 matches your hashset. Review the `args` field for context -- encoded commands, suspicious flags, or targeting of sensitive processes (lsass.exe) indicate malicious use.

### hash2connection.py output
Each line shows: timestamp, hostname, file SHA256, remote IP, remote port. A **hit** means a known tool made a network connection -- likely C2 or data exfiltration. Cross-reference the IP against threat intel.

### multikeyword_search.py output
Matches keywords/hashes/IPs across endpoint telemetry. Returns hostname, timestamp, match context. **Note**: this script accepts BOTH plain-text keywords (like "lsass", "whoami") AND SHA256 hashes. It searches AMP activity records for string matches -- a different mechanism than hash2processarg.py which matches file identity hashes.

### lateral_movement.py output
Shows connections on monitored ports (SMB/RDP/WinRM/RPC) between internal hosts. High volume from a single source to many destinations suggests scanning or lateral movement.

### allconnections.py / dumpallURL.py output
Raw network telemetry. Look for: unusual ports (not 80/443/53), high-frequency connections to single IPs (beaconing), connections during off-hours, large data transfers (exfiltration).

## Concrete Hunt Chaining

When one hunt produces results, feed them into the next:

```bash
# Chain 1: Hash hit -> Timeline deep-dive
# If hash2processarg.py found mimikatz on host "WORKSTATION01", get its UUID from the output
# then pull its full timeline:
python3 surround.py -c config.txt -o ./investigation/ -u <connector_guid_from_output>

# Chain 2: Keyword hit -> Hash verification
# If multikeyword_search.py found "procdump" keyword, extract the SHA256 from the match
# then verify if it's a known tool:
echo "<sha256_from_output>" > verify.txt
python3 hash2processarg.py -c config.txt verify.txt --csv verification.csv

# Chain 3: Lateral movement -> Timeline on both ends
# If lateral_movement.py shows HOST_A -> HOST_B on port 445:
python3 surround.py -c config.txt -o ./source/ -u <host_a_guid>
python3 surround.py -c config.txt -o ./dest/ -u <host_b_guid>
```

## Scope Guidance (--limit)

| Environment Size | Initial Triage | Focused Hunt | Full Sweep |
|-----------------|---------------|--------------|------------|
| Small (<100 endpoints) | --limit 20 | --limit 50 | No limit |
| Medium (100-1000) | --limit 50 | --limit 200 | No limit (allow time) |
| Large (1000+) | --limit 100 | --limit 500 | No limit (schedule overnight) |

Always start with a limited scope to verify the hunt produces useful results before committing to a full sweep. Use `--csv` for any run beyond triage -- console output truncates.
