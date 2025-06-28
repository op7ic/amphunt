# amphunt

This repository contains advanced threat hunting scripts for [Cisco Secure Endpoint](https://www.cisco.com/site/us/en/products/security/endpoint-security/secure-endpoint/index.html) API. The scripts leverage the AMP API to hunt for threats, analyze endpoint behavior, and detect potential compromises across the environment using API version 0 and 1.

## Overview

The scripts are built on top of a Python library (`amp_client`) that provides:
- **Rate Limiting**: Automatic API rate limit management
- **Connection Pooling**: Improved performance through connection reuse
- **Response Caching**: Reduces redundant API calls
- **Error Handling**: Graceful degradation and automatic retries

Known Windows SHA256 hashes were taken from [WINFINGER](https://github.com/op7ic/WINFINGER) repository and can be used to hunt for potentially bad commands such as ```net user admin /add``` which rely on built-in Windows tools. Various GitHub repositories with known hacking toolkits are also hashed to provide detection capabilities.

## Installation

1. **Clone the repository:**
```bash
git clone https://github.com/op7ic/amphunt.git
cd amphunt
```

2. **Install the AMP client library:**
```bash
pip install -e .
```

3. **Configure your API credentials:**

Create a `config.txt` file (see [sample](config.txt)):
```ini
[settings]
client_id = YOUR_CLIENT_ID
api_key = YOUR_API_KEY
region = nam # nam, eu, or apjc
```

Or use environment variables:
```bash
export AMP_CLIENT_ID="your_client_id"
export AMP_API_KEY="your_api_key"
export AMP_REGION="nam"  # nam, eu, or apjc
```

## AMP API Endpoints

Choose the appropriate endpoint for your region:
- `nam` - North America (`api.amp.cisco.com`)
- `eu` - Europe (`api.eu.amp.cisco.com`)
- `apjc` - Asia Pacific, Japan, and China (`api.apjc.amp.cisco.com`)

## Script Documentation

### Timeline Analysis

#### timeliner.py
Extracts complete timeline of events for all endpoints, writing individual files for each endpoint.

**Usage:**
```bash
python3 timeliner.py -c <config file> -o <output folder>
# or
python3 timeliner.py -c config.txt -o ./timelines/
```

**Analysis tips:**
```bash
# Find newly created files
grep 'Created by' *.txt

# Find executed files
grep 'Executed by' *.txt

# Find threats
grep 'Threat' *.txt

# Find network connections
grep 'NFM' *.txt

# Find document activity
grep -E '\.doc|\.xls|\.pdf|\.ppt' *.txt

# Context around suspicious processes
grep -A 10 -B 10 -i "cmd\.exe\|rundll32\.exe\|powershell\.exe" *.txt
```

#### surround.py
Generates timeline for a specific computer by its UUID.

**Usage:**
```bash
python3 surround.py -c config.txt -o ./output/ -u <computer_uuid>
```

### Hash Analysis

#### hash2processarg.py
Searches for processes matching specific SHA256 hashes and retrieves their command-line arguments.

**Usage:**
```bash
python3 hash2processarg.py -c config.txt hashset/windows-binaries/cmd.exe.txt
python3 hash2processarg.py -c config.txt hashes.txt --csv output.csv
```

**Sample output:**
```
[+] Process SHA256 : abc123... Child SHA256: def456...
[+] 2024-01-01 10:00:00 : hostname Process name: cmd.exe args: /c whoami
```

#### hash2connection.py
Finds network connections associated with specific file hashes.

**Usage:**
```bash
python3 hash2connection.py -c config.txt hashset/hacking-tools/mimikatz.txt
python3 hash2connection.py -c config.txt suspicious_hashes.txt --csv connections.csv
```

### Network Analysis

#### allconnections.py
Dumps all network connections across all endpoints.

**Usage:**
```bash
python3 allconnections.py -c config.txt
python3 allconnections.py -c config.txt --csv all_connections.csv
python3 allconnections.py -c config.txt --no-sanitize  # Don't sanitize IPs/URLs
python3 allconnections.py -c config.txt --limit 100     # Process only 100 computers
```

**Sample output:**
```
[+] Outbound network event at hostname : workstation01
    2024-01-01 10:00:00 : outbound : workstation01 : TCP 10.0.0.100:51234 -> 93.184.216.34:443
```

#### dumpallURL.py
Extracts all URL requests from all endpoints.

**Usage:**
```bash
python3 dumpallURL.py -c config.txt
python3 dumpallURL.py -c config.txt --csv urls.csv
python3 dumpallURL.py -c config.txt --summary  # Show domain statistics
```

#### lateral_movement.py
Detects potential lateral movement by monitoring specific ports (SMB, RDP, WinRM, RPC).

**Usage:**
```bash
python3 lateral_movement.py -c config.txt
python3 lateral_movement.py -c config.txt --csv lateral_movement.csv --summary
```

**Monitored ports:**
- 139, 445 (SMB)
- 3389 (RDP)
- 5985, 5986 (WinRM)
- 135 (RPC/WMIC)

### Threat Hunting

#### multikeyword_search.py
Searches for multiple keywords, IPs, or SHA256 hashes across all endpoints.

**Usage:**
```bash
python3 multikeyword_search.py -c config.txt keywords.txt
python3 multikeyword_search.py -c config.txt keywords.txt --csv results.csv
```

**Sample keyword file:**
```
mimikatz.exe
192.168.1.100
powershell.exe -enc
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
net user /add
```

#### fresh_vulnerabilities.py
Identifies vulnerable applications with CVE details.

**Usage:**
```bash
python3 fresh_vulnerabilities.py -c config.txt
python3 fresh_vulnerabilities.py -c config.txt --csv vulnerabilities.csv --summary
```

**Output includes:**
- CVE identifiers
- CVSS scores (individual and average)
- Affected products and versions
- Reference URLs

### Statistics and Reporting

#### amp_generic_stats.py
Generates comprehensive statistics for anomaly detection.

**Usage:**
```bash
python3 amp_generic_stats.py -c config.txt
python3 amp_generic_stats.py -c config.txt --csv stats.csv
```

**Metrics collected:**
- Vulnerable applications
- Network events (NFM)
- File executions, creations, movements
- Threat detections and quarantines
- Malicious activity detections

#### getSpecificEvent.py
Extracts all events of a specific type by Event ID.

**Usage:**
```bash
python3 getSpecificEvent.py -c config.txt <event_id> output.csv

# Examples:
python3 getSpecificEvent.py -c config.txt 1090519054 threats.csv       # Threat Detected
python3 getSpecificEvent.py -c config.txt 1107296274 cloud_ioc.csv     # Cloud IOC
python3 getSpecificEvent.py -c config.txt 1107296279 vulnerable.csv    # Vulnerable Application
```

**Common Event IDs:**
- `1090519054` - Threat Detected
- `553648143` - Threat Quarantined
- `1107296272` - Executed malware
- `1107296274` - Cloud IOC
- `1107296279` - Vulnerable Application Detected
- `1107296284` - Potential Ransomware
- `553648147` - Network File Move (NFM)

## Hash Sets

The repository includes pre-computed SHA256 hashes for:

### Windows Binaries (LOLBINS)
Located in `hashset/windows-binaries/`:
- System utilities that can be abused (certutil.exe, bitsadmin.exe, etc.)
- PowerShell and scripting hosts
- Network tools (net.exe, netsh.exe)

### Hacking Tools
Located in `hashset/hacking-tools/`:
- [LaZagne](https://github.com/AlessandroZ/LaZagne) - Password recovery
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) - Credential dumping
- [Impacket](https://github.com/SecureAuthCorp/impacket) - Network protocols
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) - PowerShell post-exploitation
- [GhostPack](https://github.com/GhostPack) - .NET post-exploitation
- [Metasploit](https://github.com/rapid7/metasploit-framework) modules

### Exploits
Located in `hashset/exploits/`:
- Windows kernel exploits
- Linux kernel exploits
- Exploit-DB archives

## Hunting Examples

### Detect PowerShell Empire/Encoded Commands
```bash
echo "powershell.exe -enc" > keywords.txt
echo "powershell.exe -encoded" >> keywords.txt
echo "iex(" >> keywords.txt
python3 multikeyword_search.py -c config.txt keywords.txt --csv powershell_suspicious.csv
```

### Hunt for Credential Dumping
```bash
cat hashset/hacking-tools/mimikatz.txt > cred_tools.txt
cat hashset/windows-binaries/procdump.exe.txt >> cred_tools.txt
echo "lsass" >> cred_tools.txt
python3 multikeyword_search.py -c config.txt cred_tools.txt --csv credential_dumping.csv
```

### Identify Lateral Movement
```bash
# Check for PsExec and similar tools
python3 hash2connection.py -c config.txt hashset/psexec/psexec.exe.txt --csv psexec_connections.csv

# Monitor lateral movement protocols
python3 lateral_movement.py -c config.txt --csv lateral_movement.csv --summary

# Check for suspicious service names
echo "psexesvc" > keywords.txt
echo "paexec" >> keywords.txt
python3 multikeyword_search.py -c config.txt keywords.txt
```

### Detect Persistence Mechanisms
```bash
echo "schtasks /create" > persistence.txt
echo "reg add.*CurrentVersion\\Run" >> persistence.txt
echo "sc create" >> persistence.txt
echo "wmic.*startup" >> persistence.txt
python3 multikeyword_search.py -c config.txt persistence.txt --csv persistence.csv
```

## Best Practices

1. **Rate Limiting**: The library automatically handles rate limits

2. **Caching**: Enable caching for repeated queries:
   ```bash
   export AMP_CACHE_ENABLED=true
   export AMP_CACHE_TTL=300  # 5 minutes
   ```

3. **Output Management**: Always use `--csv` flag for large datasets to avoid console overflow.

4. **Regular Hunting**: Schedule regular hunts for:
   - New vulnerable applications
   - Suspicious network connections
   - Known malicious hashes
   - Lateral movement patterns

## Limitations

- AMP trajectory API returns maximum 500 events per endpoint
- Historical data may be limited based on retention policies
- Some events may be missed if rate limits are exceeded

## Writing New Scripts

This section explains how to create new scripts using the amp_client library.

### Basic Script Template

```python
#!/usr/bin/env python3
"""
Script Name: your_script.py
Author: Your Name
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt

your_script.py - Brief description of what your script does

This script performs [detailed description of functionality].

Usage:
	python your_script.py -c <config_file> [options]
"""

import sys
import argparse
from amp_client import AMPClient, Config
# Add other imports as needed

def main():
    parser = argparse.ArgumentParser(description='Your script description')
    parser.add_argument('-c', '--config', required=True, help='Configuration file path')
    # Add other arguments as needed
    parser.add_argument('--csv', help='Export results to CSV file')
    parser.add_argument('--limit', type=int, help='Limit number of computers to process')
    args = parser.parse_args()
    
    # Load configuration
    config = Config.from_file(args.config)
    
    # Create client and perform operations
    with AMPClient(config) as client:
        # Your code here
        pass

if __name__ == '__main__':
    main()
```

### Required Imports

#### Core imports for all scripts:
```python
from amp_client import AMPClient, Config
```

#### Additional imports based on functionality:

**For event processing:**
```python
from amp_client.models import EventType, Event
```

**For computer/trajectory data:**
```python
from amp_client.models import Computer, ComputerTrajectory, TrajectoryEvent
```

**For network events:**
```python
from amp_client.models import NetworkEvent
from amp_client.utils import NetworkEventFormatter
```

**For file events:**
```python
from amp_client.utils import FileEventFormatter
```

**For CSV/JSON export:**
```python
from amp_client.utils import CSVExporter, JSONExporter
```

**For lateral movement detection:**
```python
from amp_client.utils import LateralMovementDetector
```

**For hash validation:**
```python
from amp_client.utils import HashIdentifier, Validators
```

**For error handling:**
```python
from amp_client import AMPError, AMPAuthenticationError, AMPRateLimitError
```

### Common Patterns

#### 1. Processing all computers:
```python
with AMPClient(config) as client:
    computers = list(client.computers.list(limit=args.limit))
    
    for computer in computers:
        print(f"Processing {computer.hostname} ({computer.connector_guid})")
        # Process each computer
```

#### 2. Getting events for a computer:
```python
events = list(client.events.list(
    connector_guid=computer.connector_guid,
    limit=500 # Max 500 events
))

# Or for specific event types
events = list(client.events.list(
    connector_guid=computer.connector_guid,
    event_type=[EventType.THREAT_DETECTED, EventType.THREAT_QUARANTINED]
))
```

#### 3. Getting computer trajectory:
```python
trajectory = client.computers.get_trajectory(
    connector_guid=computer.connector_guid,
    limit=500  # Max 500 events
)

for event in trajectory.events:
    if event.file and event.file.identity:
        print(f"{event.timestamp}: {event.file.file_name} - {event.file.identity.sha256}")
```

#### 4. Exporting to CSV:
```python
# Create exporter
csv_exporter = CSVExporter(args.csv)

# Define columns
csv_exporter.write_header(['timestamp', 'hostname', 'event_type', 'description'])

# Write data
for event in events:
    csv_exporter.write_row([
        event.timestamp,
        computer.hostname,
        event.event_type_name,
        event.description
    ])

csv_exporter.close()
```

#### 5. Error handling:
```python
try:
    with AMPClient(config) as client:
        # Your code
        pass
except AMPAuthenticationError:
    print("[-] Authentication failed. Check your credentials.")
    sys.exit(1)
except AMPRateLimitError:
    print("[-] Rate limit exceeded. Try again later.")
    sys.exit(1)
except AMPError as e:
    print(f"[-] AMP API error: {e}")
    sys.exit(1)
```

### Configuration Options

The Config class accepts these parameters:
- `client_id` (required): Your AMP API client ID
- `api_key` (required): Your AMP API key
- `region`: 'nam' (default), 'eu', or 'apjc'
- `domain`: Custom API domain (auto-set by region)
- `rate_limit_buffer`: Seconds before rate limit to pause (default: 5)
- `retry_attempts`: Number of retry attempts (default: 3)
- `retry_backoff`: Backoff multiplier for retries (default: 2)
- `cache_enabled`: Enable response caching (default: False)
- `cache_ttl`: Cache time-to-live in seconds (default: 300)

### Best Practices

1. **Always use context managers**: Use `with AMPClient(config) as client:` to ensure proper cleanup
2. **Handle pagination**: The library handles pagination automatically when using `.list()` methods
3. **Add progress indicators**: For long-running operations, show progress to the user
4. **Validate inputs**: Use `Validators` class for hash and input validation
5. **Follow naming conventions**: Use descriptive variable names and follow PEP 8
6. **Add comprehensive help**: Document all command-line arguments clearly
7. **Test with limits**: Always test with `--limit` flag first before processing all computers

### Example: Creating a Custom Threat Hunter

```python
#!/usr/bin/env python3
"""
custom_hunter.py - Hunt for specific IOCs across all endpoints
"""

import sys
import argparse
from collections import defaultdict
from amp_client import AMPClient, Config
from amp_client.models import EventType
from amp_client.utils import CSVExporter, HashIdentifier

def main():
    parser = argparse.ArgumentParser(description='Hunt for custom IOCs')
    parser.add_argument('-c', '--config', required=True, help='Configuration file path')
    parser.add_argument('-i', '--iocs', required=True, help='File containing IOCs (one per line)')
    parser.add_argument('--csv', help='Export results to CSV file')
    parser.add_argument('--limit', type=int, help='Limit number of computers to process')
    args = parser.parse_args()
    
    # Load IOCs
    with open(args.iocs, 'r') as f:
        iocs = {line.strip().lower() for line in f if line.strip()}
    
    # Categorize IOCs
    hash_identifier = HashIdentifier()
    sha256_hashes = {ioc for ioc in iocs if hash_identifier.is_sha256(ioc)}
    other_iocs = iocs - sha256_hashes
    
    print(f"[+] Loaded {len(sha256_hashes)} SHA256 hashes and {len(other_iocs)} other IOCs")
    
    # Load configuration and create client
    config = Config.from_file(args.config)
    
    with AMPClient(config) as client:
        # Get computers
        computers = list(client.computers.list(limit=args.limit))
        print(f"[+] Processing {len(computers)} computers")
        
        results = []
        
        for computer in computers:
            print(f"[+] Checking {computer.hostname}")
            
            # Get trajectory
            trajectory = client.computers.get_trajectory(
                connector_guid=computer.connector_guid,
                limit=500
            )
            
            # Check each event
            for event in trajectory.events:
                # Check file hashes
                if event.file and event.file.identity:
                    if event.file.identity.sha256 in sha256_hashes:
                        results.append({
                            'timestamp': event.timestamp,
                            'hostname': computer.hostname,
                            'ioc_type': 'SHA256',
                            'ioc_value': event.file.identity.sha256,
                            'file_name': event.file.file_name,
                            'file_path': event.file.file_path
                        })
                
                # Check other IOCs in file paths and names
                if event.file:
                    for ioc in other_iocs:
                        if (event.file.file_name and ioc in event.file.file_name.lower() or
                            event.file.file_path and ioc in event.file.file_path.lower()):
                            results.append({
                                'timestamp': event.timestamp,
                                'hostname': computer.hostname,
                                'ioc_type': 'String',
                                'ioc_value': ioc,
                                'file_name': event.file.file_name,
                                'file_path': event.file.file_path
                            })
        
        # Display results
        print(f"\n[+] Found {len(results)} matches")
        for result in results:
            print(f"[!] {result['timestamp']} - {result['hostname']} - "
                  f"{result['ioc_type']}: {result['ioc_value']} - "
                  f"{result['file_name']}")
        
        # Export to CSV if requested
        if args.csv:
            csv_exporter = CSVExporter(args.csv)
            csv_exporter.write_header(list(results[0].keys()) if results else [])
            for result in results:
                csv_exporter.write_row(list(result.values()))
            csv_exporter.close()
            print(f"[+] Results exported to {args.csv}")

if __name__ == '__main__':
    main()
```

## Contributing

Contributions are welcome! Please submit issues and pull requests on GitHub.

## License

See LICENSE file

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.