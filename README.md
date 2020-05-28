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

## Limitations

AMP timeline allows to search only last 500 events so historical data might be limited

## TODO

- [ ] Output to CSV
