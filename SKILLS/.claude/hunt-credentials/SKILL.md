# Hunt: Credential Theft Detection

## Description

Detect credential dumping tools, LSASS access attempts, and credential harvesting activity. This is a composite hunt that combines hash-based detection with keyword searches to identify credential theft across the environment.

## Scripts
- **hash2processarg.py** - Detect known credential tools by hash
- **hash2connection.py** - Find C2 connections from credential tools
- **multikeyword_search.py** - Search for credential-related commands

## Execution Plan

### Step 1: Hunt for Known Credential Tools
```bash
# Mimikatz
python3 hash2processarg.py -c config.txt hashset/hacking-tools/mimikatz.txt --csv mimikatz_hunt.csv

# LaZagne (password recovery)
python3 hash2processarg.py -c config.txt hashset/hacking-tools/LaZagne.txt --csv lazagne_hunt.csv

# LaZagne Forensic modules
python3 hash2processarg.py -c config.txt hashset/hacking-tools/LaZagneForensic-dump-modules.txt --csv lazagne_forensic.csv

# GhostPack (includes Rubeus, Seatbelt, SharpDump)
python3 hash2processarg.py -c config.txt hashset/hacking-tools/GhostPack-CompiledBinaires.txt --csv ghostpack.csv

# SharpCollection
python3 hash2processarg.py -c config.txt hashset/hacking-tools/SharpCollection.txt --csv sharpcollection.csv

# Impacket (secretsdump, etc.)
python3 hash2processarg.py -c config.txt hashset/hacking-tools/impacket-example-scripts-no-libs.txt --csv impacket.csv
```

### Step 2: Hunt for Credential Dumping Commands
```bash
echo "lsass" > cred_keywords.txt
echo "sekurlsa" >> cred_keywords.txt
echo "logonpasswords" >> cred_keywords.txt
echo "credential" >> cred_keywords.txt
echo "procdump" >> cred_keywords.txt
echo "comsvcs.dll" >> cred_keywords.txt
echo "MiniDump" >> cred_keywords.txt
echo "hashdump" >> cred_keywords.txt
echo "SAM" >> cred_keywords.txt
echo "ntds.dit" >> cred_keywords.txt
echo "dcsync" >> cred_keywords.txt
echo "kerberoast" >> cred_keywords.txt
python3 multikeyword_search.py -c config.txt cred_keywords.txt --csv cred_keyword_results.csv
```

### Step 3: Check for Procdump Targeting LSASS
```bash
python3 hash2processarg.py -c config.txt hashset/windows-binaries/procdump.exe.txt --csv procdump_usage.csv
# Then grep output for "lsass" in command-line arguments
```

### Step 4: Check C2 from Credential Tools
```bash
python3 hash2connection.py -c config.txt hashset/hacking-tools/mimikatz.txt --csv mimikatz_c2.csv
python3 hash2connection.py -c config.txt hashset/hacking-tools/impacket-example-scripts-no-libs.txt --csv impacket_c2.csv
```

## MITRE ATT&CK Coverage
- T1003 - OS Credential Dumping (LSASS, SAM, NTDS)
- T1003.001 - LSASS Memory
- T1003.003 - NTDS
- T1558 - Steal or Forge Kerberos Tickets (Kerberoasting)
- T1555 - Credentials from Password Stores

## When to Use
- Post-compromise investigation for credential theft
- Proactive hunting for credential tool deployment
- Detecting LSASS dumping attempts
- Hunting for Kerberoasting or DCSync activity
- Identifying password harvesting tools

## Follow-Up Skills
- If creds stolen -> `hunt-lateral-movement` (attacker likely moved)
- If specific endpoints compromised -> `hunt-timeline` for those endpoints
- If C2 channels found -> `hunt-network` for broader C2 mapping
