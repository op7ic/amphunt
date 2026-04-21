# Hunt: Vulnerability Assessment

## Description
Identify vulnerable applications across all endpoints with CVE details, CVSS scores, and affected product versions. Use for proactive vulnerability management and attack surface reduction.

## Scripts
- **fresh_vulnerabilities.py** - Enumerate vulnerable applications with CVE data

## Usage
```bash
# Full vulnerability scan
python3 fresh_vulnerabilities.py -c config.txt

# Export with summary statistics
python3 fresh_vulnerabilities.py -c config.txt --csv vulnerabilities.csv --summary
```

## Output Includes
- CVE identifiers
- CVSS scores (individual and average per application)
- Affected product names and versions
- Reference URLs for each CVE
- Endpoint hostname and GUID

## When to Use
- Regular vulnerability hygiene checks
- Pre-hunt attack surface assessment
- Identifying endpoints running exploitable software
- Prioritizing patching based on CVSS severity
- Correlating exploits with `hashset/exploits/` hash sets

## Composite Hunt
```bash
# After finding vulnerabilities, check if exploit tools are present
python3 hash2processarg.py -c config.txt hashset/exploits/windows-kernel-exploits.txt --csv kernel_exploit_hunt.csv
```

## Follow-Up Skills
- If critical vulns found -> `hunt-hashes` with matching exploit hashsets
- If specific endpoints at risk -> `hunt-timeline` for those endpoints
- For environment-wide risk -> `hunt-stats` for statistical overview
