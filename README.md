# amphunt

This repository contains basic threat hunting scripts for [AMP4E](https://www.cisco.com/c/en/us/products/security/advanced-malware-protection/index.html) API. Scripts are heavily based on already existing code published by [Cisco Security Team](https://github.com/CiscoSecurity/) with some optimization towards handling file inputs. In addition, SHA256 hashes for specific processes were taken from [WINFINGER](https://github.com/op7ic/WINFINGER) repository. 

## hash2processarg.py

This file takes a list of SHA256 hashes as input (sample can be found in [hashset](hashset/) directory) and prints every computer with matching processes along with executed command line arguments orignating from these processes.

These 3 parameters need to be modified in the source file:

```
client_id = 'XXXXXXX' # INSERT YOU API KEY
api_key = 'XXXXXXX' # INSERT YOU API KEY
domainIP = 'hostname or domain name of AMP instance' # INSERT YOUR DOMAIN NAME/HOSTNAME WHERE AMP EXISTS
```

How to invoke:
```
python3 hash2processarg.py hashset/cmd.txt
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

## hash2connection.py

This file takes a list of SHA256 hashes as input (sample can be found in [hashset](hashset/) directory) and prints every computer with matching processes and where these processes communicates to.

These 3 parameters need to be modified in the source file:

```
client_id = 'XXXXXXX' # INSERT YOU API KEY
api_key = 'XXXXXXX' # INSERT YOU API KEY
domainIP = 'hostname or domain name of AMP instance' # INSERT YOUR DOMAIN NAME/HOSTNAME WHERE AMP EXISTS
```

How to invoke:
```
python3 hash2connection.py hashset/cmd.txt
```

## allconnections.py

This file dumps all connections recorded in AMP against specific host.

These 3 parameters need to be modified in the source file:

```
client_id = 'XXXXXXX' # INSERT YOU API KEY
api_key = 'XXXXXXX' # INSERT YOU API KEY
domainIP = 'hostname or domain name of AMP instance' # INSERT YOUR DOMAIN NAME/HOSTNAME WHERE AMP EXISTS
```

How to invoke:
```
python3 allconnections.py
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

This file dumps all URLs which hosts connect to.

These 3 parameters need to be modified in the source file:

```
client_id = 'XXXXXXX' # INSERT YOU API KEY
api_key = 'XXXXXXX' # INSERT YOU API KEY
domainIP = 'hostname or domain name of AMP instance' # INSERT YOUR DOMAIN NAME/HOSTNAME WHERE AMP EXISTS
```

How to invoke:
```
python3 dumpallURL.py
```

Sample output:
```
[+] Total computers found: 1

        [+] Querying: testbox.amp.local
                 [+] Outbound network event at hostname: testbox.amp.local
                         Host: testbox.amp.local URL: http://mirrorlist.centos.org/?release=7&arch=x86_64&repo=extras&infra=stock
```

## Limitations

AMP timeline allows to search only last 500 events so historical data might be limited


## AMP4E API Endpoints 
- ```api.eu.amp.cisco.com``` - AMP EU 
- ```api.amp.cisco.com``` - AMP
- ```api.apjc.amp.cisco.com``` - AMP APJC
## TODO

- [ ] Output to CSV
