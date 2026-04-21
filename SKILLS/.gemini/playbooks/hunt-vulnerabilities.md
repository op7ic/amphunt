# Playbook: Vulnerability Assessment

## Objective
Identify vulnerable applications with CVE details, CVSS scores, and affected versions.

## Scripts
- **fresh_vulnerabilities.py** -- Enumerate vulnerabilities with CVE data

## Commands
```bash
python3 fresh_vulnerabilities.py -c config.txt --csv vulnerabilities.csv --summary
```

## Output
- CVE identifiers, CVSS scores (individual + average)
- Affected product names and versions
- Reference URLs, endpoint hostname and GUID

## Composite Hunt
```bash
python3 hash2processarg.py -c config.txt hashset/exploits/windows-kernel-exploits.txt --csv kernel_exploits.csv
```

## Follow-Up Playbooks
- Critical vulns -> `playbooks/hunt-hashes.md` with exploit hashsets
- At-risk endpoints -> `playbooks/hunt-timeline.md`
- Environment risk -> `playbooks/hunt-stats.md`
