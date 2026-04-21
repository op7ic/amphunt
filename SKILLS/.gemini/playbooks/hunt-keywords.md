# Playbook: Keyword and IOC Search

## Objective
Search for keywords, IPs, SHA256 hashes, or string patterns across all endpoints. The most flexible tool for custom IOC hunts and ad-hoc investigations.

## Scripts
- **multikeyword_search.py** -- Multi-keyword/IOC search across all endpoints

## Commands
```bash
python3 multikeyword_search.py -c config.txt keywords.txt --csv results.csv
```

## Pre-Built Keyword Files
125 files in `keywordfiles/`: cmd.exe, powershell.exe, wmic.exe, mshta.exe, rundll32.exe, regsvr32.exe, certutil.exe, bitsadmin.exe, cscript.exe, wscript.exe, advpack.dll, comsvcs.dll, TeamViewer.exe, and 100+ more.

## Common Patterns

### Encoded PowerShell
```bash
echo "powershell.exe -enc" > ps_encoded.txt
echo "powershell.exe -encoded" >> ps_encoded.txt
echo "iex " >> ps_encoded.txt
echo "Invoke-Expression" >> ps_encoded.txt
echo "DownloadString" >> ps_encoded.txt
echo "DownloadFile" >> ps_encoded.txt
python3 multikeyword_search.py -c config.txt ps_encoded.txt --csv encoded_ps.csv
```

### Reconnaissance
```bash
echo "whoami" > recon.txt
echo "net user" >> recon.txt
echo "net group" >> recon.txt
echo "net localgroup administrators" >> recon.txt
echo "ipconfig /all" >> recon.txt
echo "systeminfo" >> recon.txt
echo "nltest /dclist" >> recon.txt
echo "qwinsta" >> recon.txt
echo "query user" >> recon.txt
python3 multikeyword_search.py -c config.txt recon.txt --csv recon.csv
```

### Data Staging
```bash
echo "rar.exe" > staging.txt
echo "7z.exe" >> staging.txt
echo "makecab" >> staging.txt
echo "tar.exe" >> staging.txt
python3 multikeyword_search.py -c config.txt staging.txt --csv staging.csv
```

## Follow-Up Playbooks
- Hashes found -> `playbooks/hunt-hashes.md`
- Network IOCs -> `playbooks/hunt-network.md`
- Persistence commands -> `playbooks/hunt-persistence.md`

## Triage Priority
| Priority | Indicators | Action |
|----------|-----------|--------|
| CRITICAL | sekurlsa, MiniDump, ntds.dit, dcsync | Immediate IR escalation |
| HIGH | -enc, Invoke-Expression, certutil -urlcache | Investigate within 1 hour |
| MEDIUM | whoami, net user, systeminfo | Review in context |
| LOW | rar.exe, 7z.exe, tar.exe | Benign unless combined with exfil |

Look for clusters, not single matches.
