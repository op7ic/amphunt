# Hunt: Keyword and IOC Search

## Description
Search for multiple keywords, IP addresses, SHA256 hashes, or string patterns across all endpoints. This is the most flexible hunting tool - use it for custom IOC searches, threat intel integration, and ad-hoc investigations.

## Scripts
- **multikeyword_search.py** - Multi-keyword/IOC search across all endpoints

## Usage
```bash
# Search using a keyword file
python3 multikeyword_search.py -c config.txt keywords.txt

# Export results
python3 multikeyword_search.py -c config.txt keywords.txt --csv results.csv
```

## Building Keyword Files
Create a text file with one keyword/IOC per line. Supports:
- Filenames: `mimikatz.exe`
- IP addresses: `192.168.1.100`
- Partial commands: `powershell.exe -enc`
- SHA256 hashes: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Arbitrary strings: `net user /add`

## Pre-Built Keyword Files (keywordfiles/)
125 keyword files available including:
- Process names: cmd.exe, powershell.exe, wmic.exe, mshta.exe, rundll32.exe, regsvr32.exe, cscript.exe, wscript.exe, certutil.exe, bitsadmin.exe
- DLLs: advpack.dll, comsvcs.dll, pcwutl.dll, shdocvw.dll
- Scripts: cl_invocation.ps1, cl_mutexverifiers.ps1
- Remote access: TeamViewer.exe, putty, plink
- And 100+ more

## Common Hunt Patterns

### Encoded PowerShell
```bash
echo "powershell.exe -enc" > ps_encoded.txt
echo "powershell.exe -encoded" >> ps_encoded.txt
echo "powershell.exe -e " >> ps_encoded.txt
echo "Invoke-Expression" >> ps_encoded.txt
echo "iex " >> ps_encoded.txt
python3 multikeyword_search.py -c config.txt ps_encoded.txt --csv encoded_ps.csv
```

### Reconnaissance Commands
```bash
echo "whoami" > recon.txt
echo "net user" >> recon.txt
echo "net group" >> recon.txt
echo "net localgroup administrators" >> recon.txt
echo "ipconfig /all" >> recon.txt
echo "systeminfo" >> recon.txt
echo "nltest /dclist" >> recon.txt
echo "dsquery" >> recon.txt
python3 multikeyword_search.py -c config.txt recon.txt --csv recon_results.csv
```

### Data Staging/Exfiltration
```bash
echo "rar.exe" > staging.txt
echo "7z.exe" >> staging.txt
echo "makecab" >> staging.txt
echo "compress" >> staging.txt
echo "tar.exe" >> staging.txt
python3 multikeyword_search.py -c config.txt staging.txt --csv staging.csv
```

## When to Use
- Integrating external threat intelligence IOCs
- Custom ad-hoc hunting hypotheses
- Searching for specific commands or filenames
- Detecting reconnaissance activity
- Any search that doesn't fit neatly into other hunt skills

## Follow-Up Skills
- If hashes found -> `hunt-hashes` for deeper hash analysis
- If network IOCs match -> `hunt-network` for connection mapping
- If persistence commands found -> `hunt-persistence`

## Triage Priority

Not all keyword matches are equal. Prioritize results:

| Priority | Indicators | Action |
|----------|-----------|--------|
| CRITICAL | sekurlsa, MiniDump, ntds.dit, dcsync | Immediate IR escalation |
| HIGH | -enc, Invoke-Expression, certutil -urlcache, bitsadmin /transfer | Investigate within 1 hour |
| MEDIUM | whoami, net user, systeminfo (recon) | Review in context of other activity |
| LOW | rar.exe, 7z.exe, tar.exe (staging) | Benign unless combined with exfil indicators |

A single LOW-priority match is rarely actionable alone. Look for clusters: recon commands on the same endpoint within the same time window, followed by staging or lateral movement.
