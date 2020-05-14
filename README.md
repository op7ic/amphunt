# amphunt

This repository contains scripts to execute basic threat hunting across corporate enviroments using [AMP4E](https://www.cisco.com/c/en/us/products/security/advanced-malware-protection/index.html). Scripts are heavily based off already existing code published by [Cisco Security Team](https://github.com/CiscoSecurity/) with some optimization towards threading and file input.

## hash_process_arg.py

Takes a list of hashes in a file (sample can be found in [hashset](hashset/) directory) and prints every computer with matching process along with executed command orignating from that hash.

Needs 3 parameters modified in the source file:

```
client_id = 'XXXXXXX' # INSERT YOU API KEY
api_key = 'XXXXXXX' # INSERT YOU API KEY
domainIP = 'hostname or domain name of AMP instance' # INSERT YOUR DOMAIN NAME/HOSTNAME WHERE AMP EXISTS
```

## hash2connection.py

Takes a list of hashes in a file (sample can be found in [hashset](hashset/) directory) and prints every computer with matching process and where this process communicates to.

Needs 3 parameters modified in the source file:

```
client_id = 'XXXXXXX' # INSERT YOU API KEY
api_key = 'XXXXXXX' # INSERT YOU API KEY
domainIP = 'hostname or domain name of AMP instance' # INSERT YOUR DOMAIN NAME/HOSTNAME WHERE AMP EXISTS
```

## multiIOCSearch.py

Takes a list of hashes in a file (sample can be found in [hashset](hashset/) directory) and prints every computer with matching process.

Needs 3 parameters modified in the source file:

```
client_id = 'XXXXXXX' # INSERT YOU API KEY
api_key = 'XXXXXXX' # INSERT YOU API KEY
domainIP = 'hostname or domain name of AMP instance' # INSERT YOUR DOMAIN NAME/HOSTNAME WHERE AMP EXISTS
```