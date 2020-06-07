# This script is based on https://github.com/CiscoSecurity/amp-04-sha256-to-network-connections/blob/master/sha256_to_network_connections.py
import sys
import requests
import configparser
import time
import gc
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
import threading

# Ignore insecure cert warnings (enable only if working with onsite-amp deployments)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Create threadpool instance with 4 workers
executor = ThreadPoolExecutor(max_workers=4)
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

def hash2connection(thObject):
    guid=thObject[0]
    payload = {'q': thObject[1]}
    sha256hash=thObject[1]
    trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
    trajectory_response = session.get(trajectory_url, params=payload, verify=False)
    # Decode JSON response
    trajectory_response_json = trajectory_response.json()
    headers=trajectory_response.headers
    # Ensure we don't cross API limits, sleep if we are approaching close to limits
    if int(headers['X-RateLimit-Remaining']) < 10:
        timeout=int(headers['X-RateLimit-Reset'])
        time.sleep(int(timeout)+5)
    # Print the hostname and GUID that is about to be queried
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
                    print("{},{},{},{},{},{},{},{},{},{},{},{}".format(
                        time,
                        guid,
                        computer_guids[guid]['hostname'],
                        'NFM',
                        sha256hash,
                        local_ip,
                        local_port,
                        remote_ip,
                        remote_port,
                        'outbound',
                        '-',
                        '-'))
                if direction == 'Incoming connection from':
                    print("{},{},{},{},{},{},{},{},{},{},{},{}".format(
                        time,
                        guid,
                        computer_guids[guid]['hostname'],
                        'NFM',
                        sha256hash,
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
                print("{},{},{},{},{},{},{},{},{},{},{},{}".format(
                        time,
                        guid,
                        computer_guids[guid]['hostname'],
                        'DFC',
                        sha256hash,
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
                    print("{},{},{},{},{},{},{},{},{},{},{},{}".format(
                        time,
                        guid,
                        computer_guids[guid]['hostname'],
                        'NFM URL',
                        sha256hash,
                        local_ip,
                        local_port,
                        remote_ip,
                        remote_port,
                        'outbound',
                        str(extractDomainFromURL(dirty_url)).replace(".","[.]"),
                        str(dirty_url).replace(".","[.]")))       
                if direction == 'Incoming connection from':
                    print("{},{},{},{},{},{},{},{},{},{},{},{}".format(
                        time,
                        guid,
                        computer_guids[guid]['hostname'],
                        'NFM URL',
                        sha256hash,
                        local_ip,
                        local_port,
                        remote_ip,
                        remote_port,
                        'inbound',
                        str(extractDomainFromURL(dirty_url)).replace(".","[.]"),
                        str(dirty_url).replace(".","[.]")))
    except:
        pass


# Validate a command line parameter was provided
if len(sys.argv) < 2:
    sys.exit('Usage:\n %s <config file> <hashfile.txt>' % sys.argv[0])

# Parse config to extract API keys
config = configparser.ConfigParser()
config.read(sys.argv[1])
client_id = config['settings']['client_id']
api_key = config['settings']['api_key']
domainIP = config['settings']['domainIP']

# Store the command line parameter
sha256hashfile = sys.argv[2]


print('date,guid,hostname,type,SHA256,source_ip,source_port,destination_ip,destination_port,direction,domain,URL')
try:
    fp = open(sha256hashfile,'r')
    for sha256hash in fp.readlines():
		# Creat session object
		# http://docs.python-requests.org/en/master/user/advanced/
		# Using a session object gains efficiency when making multiple requests
        session = requests.Session()
        session.auth = (client_id, api_key)

		# Define URL and parameters
        activity_url = 'https://{}/v1/computers/activity'.format(domainIP)
        payload = {'q': sha256hash.strip()}
		# Query API
        response = session.get(activity_url, params=payload, verify=False)
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
                if int(headers['X-RateLimit-Remaining']) < 10:
                    print("[+] Sleeping {} seconds to ensure reset clock works".format(int(headers['X-RateLimit-Reset'])))
                    time.sleep(int(headers['X-RateLimit-Reset'])+5)
                next_url = response_json['metadata']['links']['next']
                response = session.get(next_url)
                response_json = response.json()
                extractGUID(response_json['data'])

		# Query trajectory for each GUID
        for guid in computer_guids:
            executor.submit(hash2connection,(guid,sha256hash.strip()))
            
finally:
    gc.collect()
