# amphunt

This repository contains basic threat hunting scripts for [AMP4E](https://www.cisco.com/c/en/us/products/security/advanced-malware-protection/index.html) API. Scripts are heavily based on already existing code published by [Cisco Security Team](https://github.com/CiscoSecurity/) with some optimization towards handling file inputs. In addition, SHA256 hashes for specific processes were taken from [WINFINGER](https://github.com/op7ic/WINFINGER) repository. Each script takes at least config file as argument.

## hash2processarg.py

This file takes a list of SHA256 hashes as input (sample can be found in [hashset](hashset/) directory) and prints every computer with matching processes along with executed command line arguments orignating from these processes. This method can be used to quickly scan for legitimate binaries (i.e. certutil) in order to see process arguments. Please edit [config.txt](config.txt) and add appropriate API keys.

How to invoke:
```
python3 hash2processarg.py <config file.txt> <hashset/cmd.txt>
```

Sample output:
```
[+] Hunting for hash: 03D43EE1F2F4F152840F7B5D8DD3386A1C659DE7F4F7C951CBB40324C97E4C18

	[+] Computers found: 1

		[+] Querying: testbox.amp.local
		 [+] Child SHA256: 03d43ee1f2f4f152840f7b5d8dd3386a1c659de7f4f7c951cbb40324c97e4c18
		 [+] 2020-04-01T09:46:41+00:00 : testbox.amp.local Process name: powershell.exe args: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.EXE restart-computer -force

[+] Hunting for hash: 0BBF1952EE724D29F04D9EA52CAE9C8C781791D57ED127AE7B618704C3395A79

	[+] Computers found: 0

```

## hash2processarg2csv.py

This is a reimplementation of [hash2processarg.py](hash2processarg.py) file with changed output format writing CSV which can be easily redirected to output file.

How to invoke:
```
python3 hash2processarg2csv.py <config file.txt> <hashset/cmd.txt>
```

Sample output:
```
date,guid,hostname,sha256,Parent sha256,file_name,arguments
<date>,<guid>,<hostname>,<sha256>,<parent>,<filename>,<command line arguments>
<date>,<guid>,<hostname>,<sha256>,<parent>,<filename>,<command line arguments>
<date>,<guid>,<hostname>,<sha256>,<parent>,<filename>,<command line arguments>
```

## hash2connection.py

This file takes a list of SHA256 hashes as input (sample can be found in [hashset](hashset/) directory) and prints every computer with matching processes and where these processes communicates to. Please edit [config.txt](config.txt) and add appropriate API keys.


How to invoke:
```
python3 hash2connection.py <config file.txt> <hashset/cmd.txt>
```

## allconnections.py

This file dumps all connections recorded in AMP against specific host. Please edit [config.txt](config.txt) and add appropriate API keys.


How to invoke:
```
python3 allconnections.py <config file.txt>
```

Sample output:
```
[+] Total computers found: 1

        [+] Querying: testbox.amp.local
                 [+] Outbound network event at hostname: testbox.amp.local
                         Host: testbox.amp.local TCP 99.99.99.99:56846 -> 18.225.36.18:80
                         Host: testbox.amp.local URL: http://mirrorlist.centos.org/?release=7&arch=x86_64&repo=extras&infra=stock
```

## dumpallURL.py

This file dumps all URLs which hosts connect to. Please edit [config.txt](config.txt) and add appropriate API keys.

How to invoke:
```
python3 dumpallURL.py <config file.txt>
```

Sample output:
```
[+] Total computers found: 1

        [+] Querying: testbox.amp.local
                 [+] Outbound network event at hostname: testbox.amp.local
                         Host: testbox.amp.local URL: http://mirrorlist.centos.org/?release=7&arch=x86_64&repo=extras&infra=stock
```


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

## Limitations

AMP timeline allows to search only last 500 events so historical data might be limited


## AMP4E API Endpoints 

- ```api.eu.amp.cisco.com``` - AMP EU 
- ```api.amp.cisco.com``` - AMP
- ```api.apjc.amp.cisco.com``` - AMP APJC

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
```

## TODO

- [ ] Output to CSV
