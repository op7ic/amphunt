# Hunt: Hash-Based IOC Hunting

## Objective
Search for known malicious or suspicious file hashes across all endpoints. Map SHA256 hashes to process executions with command-line arguments and to network connections.

## Scripts
- **hash2processarg.py** -- Find processes matching SHA256 hashes + their command-line arguments
- **hash2connection.py** -- Find network connections associated with specific file hashes

## Commands

### Process Argument Hunting
```bash
python3 hash2processarg.py -c config.txt hashset/hacking-tools/mimikatz.txt --csv mimikatz.csv
python3 hash2processarg.py -c config.txt hashset/windows-binaries/certutil.exe.txt --csv certutil.csv
python3 hash2processarg.py -c config.txt hashset/windows-binaries/cmd.exe.txt --csv cmd_activity.csv
python3 hash2processarg.py -c config.txt hashset/windows-binaries/powershell.exe.txt --csv ps_activity.csv
```

### Network Connection Hunting
```bash
python3 hash2connection.py -c config.txt hashset/hacking-tools/impacket-example-scripts-no-libs.txt --csv impacket_net.csv
python3 hash2connection.py -c config.txt hashset/psexec/psexec.exe.txt --csv psexec_net.csv
```

## Available Hash Sets
- **hashset/hacking-tools/** (26 files): GhostPack, LaZagne, impacket, PowerSploit, PoshC2, SharpCollection, metasploit, responder, netcat, burp, and more
- **hashset/windows-binaries/** (81 files): cmd.exe, powershell.exe, certutil.exe, bitsadmin.exe, mshta.exe, rundll32.exe, schtasks.exe, wmic.exe, and more
- **hashset/exploits/** (5 files): Windows/Linux kernel exploits, Exploit-DB
- **hashset/psexec/** (3 files): psexec.exe, psexec64.exe, psexesvc.exe
- **hashset/windows-dll/** (11 files): Commonly abused DLLs
- **hashset/sysinternals/** (3 files): Sysinternals suite
- **hashset/putty_plink/** (2 files): SSH/tunneling tools
- **hashset/teamviewer/** (1 file): Remote access
- **hashset/msoffice/** (2 files): Office binaries

## Combining Hash Sets
```bash
cat hashset/hacking-tools/LaZagne.txt hashset/hacking-tools/GhostPack-CompiledBinaires.txt > combined.txt
python3 hash2processarg.py -c config.txt combined.txt --csv combined_hunt.csv
```

## Follow-Up
- Encoded commands in args -> `instructions/hunt-keywords.md`
- Network C2 found -> `instructions/hunt-network.md`
- Credential tools detected -> `instructions/hunt-credentials.md`
