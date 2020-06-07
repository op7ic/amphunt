# This script is based on https://github.com/CiscoSecurity/amp-04-sha256-to-network-connections/blob/master/sha256_to_network_connections.py
import sys
import requests
import configparser
import time
import gc
from urllib.parse import urlparse

# Ignore insecure cert warnings (enable only if working with onsite-amp deployments)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Containers for GUIDs
computer_guids = {}

def extractGUID(data):
    """ Extract GUIDs from data structure and store them in computer_guids variable"""
    for entry in data:
        connector_guid = entry['connector_guid']
        hostname = entry['hostname']
        computer_guids.setdefault(connector_guid, {'hostname':hostname})

def extractDomainFromURL(url):
    """ Extract domain name from URL"""
    return urlparse(url).netloc

# Validate a command line parameter was provided
if len(sys.argv) < 2:
    sys.exit('Usage: <config file.txt>\n %s' % sys.argv[0])

# Parse config to extract API keys
config = configparser.ConfigParser()
config.read(sys.argv[1])
client_id = config['settings']['client_id']
api_key = config['settings']['api_key']
domainIP = config['settings']['domainIP']

#Print header for CSV 
print('date,guid,hostname,source_ip,source_port,destination_ip,destination_port,direction,domain,URL')

try:
    # Creat session object
    # http://docs.python-requests.org/en/master/user/advanced/
    # Using a session object gains efficiency when making multiple requests
    session = requests.Session()
    session.auth = (client_id, api_key)

    # Define URL for extraction of all computers
    computers_url='https://{}/v1/computers'.format(domainIP)
    response = session.get(computers_url, verify=False)
    # Get Headers
    headers=response.headers
    # Ensure we don't cross API limits, sleep if we are approaching close to limits
    if int(headers['X-RateLimit-Remaining']) < 10:
        time.sleep(int(headers['X-RateLimit-Reset'])+5)
    # Decode JSON response
    response_json = response.json()
    #Page 1 extract all GUIDs
    extractGUID(response_json['data'])

    # Handle paginated pages and extract computer GUIDs
    if('next' in response_json['metadata']['links']):
        while 'next' in response_json['metadata']['links']:
            next_url = response_json['metadata']['links']['next']
            response = session.get(next_url)
            headers=response.headers
            # Ensure we don't cross API limits, sleep if we are approaching close to limits
            if int(headers['X-RateLimit-Remaining']) < 10:
                timeout=int(headers['X-RateLimit-Reset'])
                time.sleep(timeout+5)
            # Extract
            response_json = response.json()
            extractGUID(response_json['data'])


    for guid in computer_guids:
        trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
        trajectory_response = session.get(trajectory_url, verify=False)
        trajectory_response_json = trajectory_response.json()

        try:
            events = trajectory_response_json['data']['events']
            for event in events:
                event_type = event['event_type']
                time = event['date']
                if event_type == 'NFM':
                    network_info = event['network_info']
                    protocol = network_info['nfm']['protocol']
                    local_ip = network_info['local_ip']
                    local_port = network_info['local_port']
                    remote_ip = network_info['remote_ip']
                    remote_port = network_info['remote_port']
                    direction = network_info['nfm']['direction']
                    if direction == 'Outgoing connection from':
                        print("{},{},{},{},{},{},{},{},{},{},{}".format(
                            time,
                            guid,
                            computer_guids[guid]['hostname'],
                            'NFM',
                            local_ip,
                            local_port,
                            remote_ip,
                            remote_port,
                            'outbound',
                            '-',
                            '-'))
                    if direction == 'Incoming connection from':
                        print("{},{},{},{},{},{},{},{},{},{},{}".format(
                            time,
                            guid,
                            computer_guids[guid]['hostname'],
                            'NFM',
                            local_ip,
                            local_port,
                            remote_ip,
                            remote_port,
                            'inbound',
                            '-',
                            '-'))
                if event_type == 'DFC Threat Detected':
                    network_info = event['network_info']
                    local_ip = network_info['local_ip']
                    local_port = network_info['local_port']
                    remote_ip = network_info['remote_ip']
                    remote_port = network_info['remote_port']
                    print("{},{},{},{},{},{},{},{},{},{},{}".format(
                            time,
                            guid,
                            computer_guids[guid]['hostname'],
                            'DFC',
                            local_ip,
                            local_port,
                            remote_ip,
                            remote_port,
                            'DFC Threat Detected',
                            '-',
                            '-'))                    
                if event_type == 'NFM' and 'dirty_url' in str(event):
                    network_info = event['network_info']
                    dirty_url= event['network_info']['dirty_url']
                    protocol = network_info['nfm']['protocol']
                    local_ip = network_info['local_ip']
                    local_port = network_info['local_port']
                    remote_ip = network_info['remote_ip']
                    remote_port = network_info['remote_port']
                    direction = network_info['nfm']['direction']
                    if direction == 'Outgoing connection from':
                        print("{},{},{},{},{},{},{},{},{},{},{}".format(
                            time,
                            guid,
                            computer_guids[guid]['hostname'],
                            'NFM URL',
                            local_ip,
                            local_port,
                            remote_ip,
                            remote_port,
                            'outbound',
                            str(extractDomainFromURL(dirty_url)).replace(".","[.]"),
                            str(dirty_url).replace(".","[.]")))       
                    if direction == 'Incoming connection from':
                        print("{},{},{},{},{},{},{},{},{},{},{}".format(
                            time,
                            guid,
                            computer_guids[guid]['hostname'],
                            'NFM URL',
                            local_ip,
                            local_port,
                            remote_ip,
                            remote_port,
                            'inbound',
                            str(extractDomainFromURL(dirty_url)).replace(".","[.]"),
                            str(dirty_url).replace(".","[.]")))
        except:
            pass
finally:
    gc.collect()
