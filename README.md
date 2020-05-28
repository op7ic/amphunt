# amphunt

This repository contain basic threat hunting scripts for [AMP4E](https://www.cisco.com/c/en/us/products/security/advanced-malware-protection/index.html) API. Scripts are heavily based off already existing code published by [Cisco Security Team](https://github.com/CiscoSecurity/) with some optimization towards threading and file input. In addition, SHA256 hashes for specific process names were taken from (WINFINGER)[https://github.com/op7ic/WINFINGER] repository. 

## hash2processarg.py

Takes a list of SHA256 hashes in a file (sample can be found in [hashset](hashset/) directory) and prints every computer with matching process along with executed command line arguments orignating from that process.

Needs 3 parameters modified in the source file:

```
client_id = 'XXXXXXX' # INSERT YOU API KEY
api_key = 'XXXXXXX' # INSERT YOU API KEY
domainIP = 'hostname or domain name of AMP instance' # INSERT YOUR DOMAIN NAME/HOSTNAME WHERE AMP EXISTS
```

## hash2connection.py

Takes a list of SHA256 hashes in a file (sample can be found in [hashset](hashset/) directory) and prints every computer with matching process and where this process communicates to.

Needs 3 parameters modified in the source file:

```
client_id = 'XXXXXXX' # INSERT YOU API KEY
api_key = 'XXXXXXX' # INSERT YOU API KEY
domainIP = 'hostname or domain name of AMP instance' # INSERT YOUR DOMAIN NAME/HOSTNAME WHERE AMP EXISTS
```


## TODO

- [ ] Output to CSV
