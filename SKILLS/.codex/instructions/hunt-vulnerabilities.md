# Hunt: Vulnerability Assessment

## Objective
Identify vulnerable applications across all endpoints with CVE details, CVSS scores, and affected product versions.

## Scripts
- **fresh_vulnerabilities.py** -- Enumerate vulnerable applications with CVE data

## Commands
```bash
python3 fresh_vulnerabilities.py -c config.txt --csv vulnerabilities.csv --summary
```

## Output Includes
- CVE identifiers and CVSS scores (individual + average)
- Affected product names and versions
- Reference URLs for each CVE
- Endpoint hostname and GUID

## When to Use
- Regular vulnerability hygiene checks
- Pre-hunt attack surface assessment
- Prioritizing patching by CVSS severity
- Correlating with exploit hashsets

## Composite Hunt
```bash
python3 hash2processarg.py -c config.txt hashset/exploits/windows-kernel-exploits.txt --csv kernel_exploits.csv
```

## Follow-Up
- Critical vulns found -> `instructions/hunt-hashes.md` with exploit hashsets
- Specific endpoints at risk -> `instructions/hunt-timeline.md`
- Environment-wide risk -> `instructions/hunt-stats.md`
