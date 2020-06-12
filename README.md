# amphunt

This repository contains basic threat hunting scripts for [AMP4E](https://www.cisco.com/c/en/us/products/security/advanced-malware-protection/index.html) API. Scripts are heavily based on already existing code published by [Cisco Security Team](https://github.com/CiscoSecurity/) with some optimization towards handling file inputs, csv output and pagination. Known Windows SHA256 hashes were taken from [WINFINGER](https://github.com/op7ic/WINFINGER) repository and can be used to hunt for potentially bad commands such as ```net user admin /add``` which rely on built-in Windows tool. In addition, various GitHub repositories with known hacking toolkits, such as [sqlmap](https://github.com/sqlmapproject/sqlmap), [LaZagne](https://github.com/AlessandroZ/LaZagne) were also hashed to provide the ability for hunting on both current and past versions of these tools. Please be aware that each script takes at least a config file as argument. Sample config file [here](config.txt).

## hash2processarg.py

This script takes a list of SHA256 hashes as input (sample can be found in [hashset](hashset/) directory) and prints every computer name with matching processes along with the executed command line arguments orignating from these processes. This method can be used to quickly scan for legitimate binaries (i.e. certutil) in order to see process arguments or to hunt for malicious processes launched by specific hash. Please edit [config.txt](config.txt) and add appropriate API keys.

How to invoke:
```
python3 hash2processarg.py <config file.txt> <hashset/cmd.txt>
```

Sample output:
```
[+] 2020-04-01T09:46:41+00:00 : testbox.amp.local Process name: powershell.exe args: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.EXE restart-computer -force
```

## hash2processarg2csv.py

This is a reimplementation of [hash2processarg.py](hash2processarg.py) file with changed output format writing CSV which can be easily redirected to output file.

How to invoke:
```
python3 hash2processarg2csv.py <config file.txt> <hashset/cmd.txt> > output.csv
```

Sample output:
```
date,guid,hostname,sha256,Parent sha256,file_name,arguments
<date>,<guid>,<hostname>,<sha256>,<parent>,<filename>,<command line arguments>
<date>,<guid>,<hostname>,<sha256>,<parent>,<filename>,<command line arguments>
<date>,<guid>,<hostname>,<sha256>,<parent>,<filename>,<command line arguments>
```

## hash2connection.py

This script takes a list of SHA256 hashes as input (sample can be found in [hashset](hashset/) directory) and prints every computer with matching processes and where these processes communicates to. Please edit [config.txt](config.txt) and add appropriate API keys.


How to invoke:
```
python3 hash2connection.py <config file.txt> <hashset/cmd.txt>
```

## hash2connection2csv.py

This is a reimplementation of [hash2connection.py](hash2connection.py) file with changed output format writing CSV which can be easily redirected to output file.


How to invoke:
```
python3 hash2connection2csv.py <config file.txt> <hashset/cmd.txt>
```
Sample output:
```
date,guid,hostname,type,SHA256,source_ip,source_port,destination_ip,destination_port,direction,domain,URL
<date>,<guid>,<hostname>,<type of telemetry>,<sha256>,<source IP>,<source port>,<destination IP>,<destination port>,<inbound/outbound>,<domain>,<URL>
<date>,<guid>,<hostname>,<type of telemetry>,<sha256>,<source IP>,<source port>,<destination IP>,<destination port>,<inbound/outbound>,<domain>,<URL>
```

## allconnections.py

This script dumps all connections recorded in AMP against all hosts. Please edit [config.txt](config.txt) and add appropriate API keys.

How to invoke:
```
python3 allconnections.py <config file.txt>
```

Sample output:
```
Host: testbox.amp.local TCP 99.99.99.99:56846 -> 18.225.36.18:80                       
```

## allconnections2csv.py

This is a reimplementation of [allconnections.py](allconnections.py) file with changed output format writing CSV which can be easily redirected to output file.

How to invoke:
```
python3 allconnections2csv.py <config file.txt> > output.csv
```

Sample output:
```
date,guid,hostname,telemetry source,source_ip,source_port,destination,destination port,direction,domain,URL
<date>,<guid>,<hostname>,<telemetry>,<source IP>,<source port>,<destination IP>,<destination port>,<inbound/outbound>,<domain>,<URL>
<date>,<guid>,<hostname>,<telemetry>,<source IP>,<source port>,<destination IP>,<destination port>,<inbound/outbound>,<domain>,<URL>
```

## dumpallURL.py

This script dumps all accessed URLs for all hosts. Please edit [config.txt](config.txt) and add appropriate API keys.

How to invoke:
```
python3 dumpallURL.py <config file.txt>
```

Sample output:
```
Host: testbox.amp.local URL: http://mirrorlist.centos.org/?release=7&arch=x86_64&repo=extras&infra=stock
```

## dumpallURL2csv.py

This is a reimplementation of [dumpallURL.py](dumpallURL.py) file with changed output format writing CSV which can be easily redirected to output file.

How to invoke:
```
python3 dumpallURL2csv.py <config file.txt> > output.csv
```

Sample output:
```
date,guid,hostname,type,source ip,source port,destination ip,destination port,direction,domain,URL
<date>,<guid>,<hostname>,<type>,<source ip>,<source port>,<destination ip>,<destination port>,<direction>,<domain>,<URL>
```

## multikeyword_search.py

This script takes a config file and list with keywords (one per line) and searches for processes/commands/network connections related to these keywords.

How to invoke:
```
python3 multikeyword_search.py <config file.txt> <keyword file>
```

Sample keyword file:
```
winword.exe
explorer.exe
192.168.20.2
explorer.exe
rundll32.exe
notepad.exe
notepad64
ransom
```

## lateral_movement.py

This script tracks connections to RDP/WMIC/WINRM/SMB.

How to invoke:
```
python3 lateral_movement.py <config file.txt>
```

## fresh_vulnerabilities2csv.py

This script dumps all vulnerabilities observed across all trajectories (with 500 events limit) and prints it in CSV format. It will print out information about oldest CVE/CVSS as well as averaged CVSS score, along with other information.

How to invoke:
```
python3 all_vulnerabilities2csv.py <config file.txt> > output.csv
```

Sample output:
```
date,guid,hostname,type,severity,file_name,file_sha256,product_name,oldest_CVE,oldest_version_impacted,oldest_cvss_score,average_cvss,all_CVE,oldest_reference_url
<date>,<guid>,<hostname>,<type>,<severity>,<file_name>,<file_sha256>,<product_name>,<oldest_CVE>,<oldest_version_impacted>,<oldest_cvss_score>,average_cvss,all_CVE,oldest_reference_url
```

## amp_generic_stats.py

This script will create a csv file with statistic gathered against each of the hosts in the AMP installation so they can be searched for [anomalies](https://vpotapov.wordpress.com/2017/03/20/event-aggregation/). It targets, specific parameters such as:

- Number of created/moved/executed files
- Number of network connections
- Number of specific AMP alerts such as 'Threat Quarantined' or 'Malware Executed'

## getSpecificEvent.py

This file extracts specific events from AMP API, identified by Event ID, and exports them to CSV file. Please edit [config.txt](config.txt) and add appropriate API keys.

How to invoke:

```
python3 getSpecificEvent.py <config file> <event_number> <CSV file name>
i.e.
python3 getSpecificEvent.py config.txt 1107296274 cloud.ioc.csv
```

Example output:
```
[+] Total results: 3452
[+] Event Type: Cloud IOC
[+] Dumped 3452 lines to cloud.ioc.csv
```

List of available event codes can be retrieved using [API function event_types](https://api-docs.amp.cisco.com/api_actions/details?api_action=GET+%2Fv1%2Fevent_types&api_host=api.amp.cisco.com&api_resource=Event+Type&api_version=v1):

```
553648130 : Policy Update
554696714 : Scan Started
554696715 : Scan Completed, No Detections
1091567628 : Scan Completed With Detections
2165309453 : Scan Failed
1090519054 : Threat Detected
553648143 : Threat Quarantined
2164260880 : Quarantine Failure
570425394 : Quarantine Restore Requested
553648149 : Quarantined Item Restored
2164260884 : Quarantine Restore Failed
2181038130 : Quarantine Request Failed to be Delivered
553648154 : Cloud Recall Restore from Quarantine
553648155 : Cloud Recall Quarantine Successful
2164260892 : Cloud Recall Restore from Quarantine Failed
2164260893 : Cloud Recall Quarantine Attempt Failed
553648158 : Install Started
2164260895 : Install Failure
553648166 : Uninstall
2164260903 : Uninstall Failure
1003 : Email Confirmation
1004 : Forgotten Password Reset
1005 : Password Has Been Reset
2164260866 : Policy Update Failure
553648146 : Cloud Recall Restore of False Positive
553648147 : Cloud Recall Detection
553648168 : Execution Blocked
553648150 : Quarantine Restore Started
570425396 : Application Registered
570425397 : Application Deregistered
570425398 : Application Authorized
570425399 : Application Deauthorized
1090524040 : APK Threat Detected
1090524041 : APK Custom Threat Detected
1090519084 : DFC Threat Detected
1107296261 : Adobe Reader compromise
1107296262 : Microsoft Word compromise
1107296263 : Microsoft Excel compromise
1107296264 : Microsoft PowerPoint compromise
1107296266 : Adobe Reader launched a shell
1107296267 : Microsoft Word launched a shell
1107296268 : Microsoft Excel launched a shell
1107296269 : Microsoft PowerPoint launched a shell
1107296270 : Apple QuickTime compromise
1107296271 : Apple QuickTime launched a shell
1107296272 : Executed malware
1107296273 : Suspected botnet connection
553648170 : Reboot Pending
553648171 : Reboot Completed
1107296274 : Cloud IOC
1107296275 : Microsoft Calculator compromise
1107296276 : Microsoft Notepad compromise
553648173 : File Fetch Completed
2164260910 : File Fetch Failed
554696756 : Endpoint IOC Scan Started
554696757 : Endpoint IOC Scan Completed, No Detections
1091567670 : Endpoint IOC Scan Completed With Detections
2165309495 : Endpoint IOC Scan Failed
2164260914 : Endpoint IOC Definition Update Failure
553648179 : Endpoint IOC Definition Update Success
2164260911 : Endpoint IOC Configuration Update Failure
553648176 : Endpoint IOC Configuration Update Success
1090519089 : Endpoint IOC Scan Detection Summary
1107296277 : Connection to suspicious domain
1107296278 : Threat Detected in Low Prevalence Executable
1107296279 : Vulnerable Application Detected
1107296280 : Suspicious Download
1107296281 : Microsoft CHM Compromise
1107296282 : Suspicious Cscript Launch
1090519096 : Update: Reboot Required
1090519097 : Update: Reboot Advised
2164260922 : Update: Unexpected Reboot Required
553648137 : Product Update Failed
553648135 : Product Update Started
553648136 : Product Update Completed
1107296285 : Cognitive Incident
1107296284 : Potential Ransomware
1107296283 : Possible Webshell
1090519103 : Exploit Prevention
2164260931 : Critical Fault Raised
1090519107 : Major Fault Raised
553648195 : Minor Fault Raised
553648196 : Fault Cleared
1090519081 : Rootkit Detection
1090519105 : Malicious Activity Detection
1090519102 : iOS Network Detection
553648199 : Malicious Activity Block
1090519112 : System Process Protection
553648202 : Endpoint Isolation Start Success
2164260939 : Endpoint Isolation Start Failure
553648204 : Endpoint Isolation Stop Success
2164260941 : Endpoint Isolation Stop Failure
553648206 : Endpoint Isolation Update Success
2164260943 : Endpoint Isolation Update Failure
553648208 : Orbital Install Success
2164260945 : Orbital Install Failure
553648210 : Orbital Update Success
2164260947 : Orbital Update Failure
553648215 : Endpoint Isolation Unlock Limit Reached
1107296257 : Potential Dropper Infection
1107296258 : Multiple Infected Files
1107296344 : SecureX Threat Hunting Incident
```

## AMP4E API Endpoints 

AMP API endpoint need to be specified in the config file under 'domainIP' parameter. Please choose one depending on location of your console:

- ```api.eu.amp.cisco.com``` - AMP EU 
- ```api.amp.cisco.com``` - AMP
- ```api.apjc.amp.cisco.com``` - AMP APJC

## GitHub hashes for popular hacking tools:

Various GitHub repositories can also be used for hunting. SHA256 hashes from these repositories, along with historic versions, are captured in the [hashset](hashset/) directory under either the [exploits](hashset/exploits) folder or the [hacking-tools](hashset/hacking-tools). At present, the following repositories are fully hashed (including all historical commits):

- [linux-kernel-exploits](https://github.com/SecWiki/linux-kernel-exploits)
- [LaZagne](https://github.com/AlessandroZ/LaZagne)
- [BeRoot](https://github.com/AlessandroZ/BeRoot)
- [LaZagneForensic](https://github.com/AlessandroZ/LaZagneForensic)
- [Ghostpack-CompiledBinaries](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)
- [PowerSCCM](https://github.com/PowerShellMafia/PowerSCCM)
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
- [PoshC2_Old](https://github.com/nettitude/PoshC2_Old)
- [impacket](https://github.com/SecureAuthCorp/impacket)
- [PoshC2](https://github.com/nettitude/PoshC2)
- [windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)
- [sqlmap](https://github.com/sqlmapproject/sqlmap)
- [SharpCollection](https://github.com/Flangvik/SharpCollection)
- [exploitdb](https://github.com/offensive-security/exploitdb)

## [LOLBIN](https://lolbas-project.github.io/)

[LOLBIN](https://lolbas-project.github.io/) SHA256 hashes (and other core windows tools worth hunting for) can be found in either [windows-binaries](hashset/windows-binaries) or [windows-dll](hashset/windows-dll). In partifular, [hash2processarg.py](hash2processarg.py) or [multikeyword_searchis.py](multikeyword_searchis.py) are very handy when hunting for LOLBINS since it will show associated command line arguments or network connections. 


## Examples of useful things to grep and search for:

```
rundll32 + url.dll
net + admin or domain
net + use of weak credentials to mount network share
powershell + iex
powershell + "==" (for base64)
cmd + whoami
net + use + http or \\ (for webdav)
psexec + use of -s or cmd with password
procdump + lsass
psexec-svc
nltest
net + administrator
vulnerable software (using event code 1107296279)
wevtutil.exe cl (cleanup ofr event logs)
hacking tools (see hashset/hacking-tools folder)
sc command disabling any of criticial security services such as SepMasterService, SAVAdminService, wscsvc, wuauserv, SavService ,MpsSvc
mshta + ActiveXObject
javascript + ActiveXObject 
WScript + javascript
w3wp spawning powershell/cmd writing to files
http[s]/webdav url passed to lolbins 
reg + HKLM\SAM
winrm.vbs
winrm
```


## Limitations

- AMP activity trajectory allows to search only last 500 events so historical data might be limited. 
- Experimental threading scripts are in [asyncio](https://github.com/op7ic/amphunt/tree/asyncio) directory. These are under developement.

## Prerequisites 

- Python3.6+

## TODO

- [x] Output to CSV
- [x] Handle pagination
- [ ] Optimize output
- [ ] Better exception / error handling / code quality. These tools are mostly PoC for now
- [ ] Threading
- [x] Hash various security tools/exploits from public repos