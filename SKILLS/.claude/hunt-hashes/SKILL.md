# Hunt: Hash-Based IOC Hunting

## Description
Search for known malicious or suspicious file hashes across all endpoints. Maps SHA256 hashes to process executions with command-line arguments and network connections. Use when you have specific IOC hashes or want to detect known offensive tools.

## Scripts
- **hash2processarg.py** - Find processes matching SHA256 hashes + their command-line arguments
- **hash2connection.py** - Find network connections associated with specific file hashes

## Usage

### Hunt by Process Arguments
```bash
# Hunt for a specific tool's hashes
python3 hash2processarg.py -c config.txt hashset/hacking-tools/mimikatz.txt

# Hunt for LOLBIN abuse (e.g., certutil used for downloads)
python3 hash2processarg.py -c config.txt hashset/windows-binaries/certutil.exe.txt

# Export to CSV
python3 hash2processarg.py -c config.txt hashset/windows-binaries/cmd.exe.txt --csv cmd_activity.csv
```

### Hunt by Network Connections
```bash
# Find network connections from known hacking tools
python3 hash2connection.py -c config.txt hashset/hacking-tools/mimikatz.txt

# Check if PsExec made network connections
python3 hash2connection.py -c config.txt hashset/psexec/psexec.exe.txt --csv psexec_net.csv
```

## Available Hash Sets

### Hacking Tools (hashset/hacking-tools/)
BeRoot, EchoMirage, GhostPack, LaZagne, LaZagneForensic, PoshC2, PowerSCCM, PowerSploit, SharpCollection, burp, fget.exe, impacket, l0pht, metasploit (C/C++, class, DLL/EXE/PS1), netcat, npf.sys, responder, and more.

### Windows LOLBINS (hashset/windows-binaries/)
81 binaries including: at.exe, bitsadmin.exe, certutil.exe, cmd.exe, cmstp.exe, csc.exe, cscript.exe, msbuild.exe, mshta.exe, powershell.exe, psexec.exe, reg.exe, regsvr32.exe, rundll32.exe, schtasks.exe, wmic.exe, wscript.exe, and more.

### Other Categories
- hashset/exploits/ - Windows/Linux kernel exploits, Exploit-DB
- hashset/psexec/ - PsExec variants (psexec.exe, psexec64.exe, psexesvc.exe)
- hashset/windows-dll/ - 11 DLLs commonly abused
- hashset/sysinternals/ - Sysinternals suite
- hashset/putty_plink/ - SSH/tunneling tools
- hashset/teamviewer/ - Remote access
- hashset/msoffice/ - Office binaries

## Combining Hash Sets
```bash
# Combine multiple sets for broader hunting
cat hashset/hacking-tools/mimikatz.txt hashset/hacking-tools/LaZagne.txt > combined_cred_tools.txt
python3 hash2processarg.py -c config.txt combined_cred_tools.txt --csv cred_hunt.csv
```

## When to Use
- Hunting for known malware/tool execution
- Detecting LOLBIN abuse
- Searching for specific IOC hashes from threat intel
- Investigating tool deployment across environment

## Follow-Up Skills
- If process args reveal encoded commands -> `hunt-keywords` with decoded content
- If network connections found -> `hunt-network` for broader analysis
- If credential tools detected -> `hunt-credentials` for focused hunt
