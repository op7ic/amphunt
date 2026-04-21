# Playbook: Hash-Based IOC Hunting

## Objective
Search for known malicious or suspicious file hashes across all endpoints. Map SHA256 hashes to process executions with command-line arguments and to network connections.

## Scripts
- **hash2processarg.py** -- SHA256 -> process executions + command-line arguments
- **hash2connection.py** -- SHA256 -> network connections (C2 detection)

## Commands

### Process Argument Hunting
```bash
python3 hash2processarg.py -c config.txt hashset/hacking-tools/mimikatz.txt --csv mimikatz.csv
python3 hash2processarg.py -c config.txt hashset/windows-binaries/certutil.exe.txt --csv certutil.csv
python3 hash2processarg.py -c config.txt hashset/windows-binaries/cmd.exe.txt --csv cmd.csv
python3 hash2processarg.py -c config.txt hashset/windows-binaries/powershell.exe.txt --csv ps.csv
python3 hash2processarg.py -c config.txt hashset/windows-binaries/mshta.exe.txt --csv mshta.csv
python3 hash2processarg.py -c config.txt hashset/windows-binaries/bitsadmin.exe.txt --csv bitsadmin.csv
```

### Network Connection Hunting
```bash
python3 hash2connection.py -c config.txt hashset/hacking-tools/impacket-example-scripts-no-libs.txt --csv impacket_net.csv
python3 hash2connection.py -c config.txt hashset/psexec/psexec.exe.txt --csv psexec_net.csv
```

## Available Hash Sets
- **hashset/hacking-tools/** (26): GhostPack, LaZagne, impacket, PowerSploit, PoshC2, SharpCollection, metasploit, responder, netcat, burp, etc.
- **hashset/windows-binaries/** (81): cmd.exe, powershell.exe, certutil.exe, bitsadmin.exe, mshta.exe, rundll32.exe, schtasks.exe, wmic.exe, etc.
- **hashset/exploits/** (5): Windows/Linux kernel exploits, Exploit-DB
- **hashset/psexec/** (3): psexec.exe, psexec64.exe, psexesvc.exe
- **hashset/windows-dll/** (11): Commonly abused DLLs
- **hashset/sysinternals/** (3), **hashset/putty_plink/** (2), **hashset/teamviewer/** (1), **hashset/msoffice/** (2)

## Combining Hash Sets
```bash
cat hashset/hacking-tools/LaZagne.txt hashset/hacking-tools/GhostPack-CompiledBinaires.txt > combined.txt
python3 hash2processarg.py -c config.txt combined.txt --csv combined.csv
```

## Follow-Up Playbooks
- Encoded commands in args -> `playbooks/hunt-keywords.md`
- C2 connections found -> `playbooks/hunt-network.md`
- Credential tools detected -> `playbooks/hunt-credentials.md`
