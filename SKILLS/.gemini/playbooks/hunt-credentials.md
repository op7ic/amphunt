# Playbook: Credential Theft Detection

## Objective
Detect credential dumping tools, LSASS access, and credential harvesting. Composite hunt combining hash detection with keyword searches.


## Scripts
- **hash2processarg.py** -- Detect credential tools by hash
- **hash2connection.py** -- Find C2 from credential tools
- **multikeyword_search.py** -- Search for credential commands

## Execution Plan

### Step 1: Known Credential Tools
```bash
python3 hash2processarg.py -c config.txt hashset/hacking-tools/mimikatz.txt --csv mimikatz.csv
python3 hash2processarg.py -c config.txt hashset/hacking-tools/GhostPack-CompiledBinaires.txt --csv ghostpack.csv
python3 hash2processarg.py -c config.txt hashset/hacking-tools/LaZagne.txt --csv lazagne.csv
python3 hash2processarg.py -c config.txt hashset/hacking-tools/LaZagneForensic-dump-modules.txt --csv lazagne_forensic.csv
python3 hash2processarg.py -c config.txt hashset/hacking-tools/impacket-example-scripts-no-libs.txt --csv impacket.csv
```

### Step 2: Credential Dumping Commands
```bash
echo "lsass" > cred_keywords.txt
echo "sekurlsa" >> cred_keywords.txt
echo "logonpasswords" >> cred_keywords.txt
echo "procdump" >> cred_keywords.txt
echo "comsvcs.dll" >> cred_keywords.txt
echo "MiniDump" >> cred_keywords.txt
echo "hashdump" >> cred_keywords.txt
echo "ntds.dit" >> cred_keywords.txt
echo "dcsync" >> cred_keywords.txt
echo "kerberoast" >> cred_keywords.txt
echo "credential" >> cred_keywords.txt
python3 multikeyword_search.py -c config.txt cred_keywords.txt --csv cred_kw.csv
```

### Step 3: Check for Procdump Targeting LSASS
```bash
python3 hash2processarg.py -c config.txt hashset/windows-binaries/procdump.exe.txt --csv procdump_usage.csv
# Review output for "lsass" in command-line arguments
```

### Step 4: C2 from Credential Tools
```bash
python3 hash2connection.py -c config.txt hashset/hacking-tools/mimikatz.txt --csv mimikatz_c2.csv
python3 hash2connection.py -c config.txt hashset/hacking-tools/impacket-example-scripts-no-libs.txt --csv impacket_c2.csv
```

## MITRE ATT&CK Coverage
- T1003 - OS Credential Dumping (LSASS, SAM, NTDS)
- T1003.001 - LSASS Memory
- T1558 - Steal or Forge Kerberos Tickets
- T1555 - Credentials from Password Stores

## Follow-Up Playbooks
- Creds stolen -> `playbooks/hunt-lateral-movement.md`
- Endpoints compromised -> `playbooks/hunt-timeline.md`
- C2 found -> `playbooks/hunt-network.md`
