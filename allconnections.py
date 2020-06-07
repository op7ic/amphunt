# This script is based on https://github.com/CiscoSecurity/amp-04-sha256-to-network-connections/blob/master/sha256_to_network_connections.py
import sys
import requests
import configparser
import time
import gc
from urllib.parse import urlparse
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
import threading

# Ignore insecure cert warnings (enable only if working with onsite-amp deployments)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Containers for output
computer_guids = {}
# Create threadpool instance with 4 workers
executor = ThreadPoolExecutor(max_workers=4)

def extractGUID(data):
    """ Extract GUIDs from data structure and store them in computer_guids variable"""
    for entry in data:
        connector_guid = entry['connector_guid']
        hostname = entry['hostname']
        computer_guids.setdefault(connector_guid, {'hostname':hostname})

def extractDomainFromURL(url):
    """ Extract domain name from URL"""
    return urlparse(url).netloc

def searchConnections(guid):
    """ Function to perform lookup on specific event type"""
    #print('\n\t[+] Querying: {} - {}'.format(computer_guids[guid]['hostname'], guid)) # this print no longer make sense due to threading
    trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
    trajectory_response = session.get(trajectory_url, verify=False)
    trajectory_response_json = trajectory_response.json()
    headers=trajectory_response.headers
    if int(headers['X-RateLimit-Remaining']) < 10:
        timeout=int(headers['X-RateLimit-Reset'])
        time.sleep(int(timeout)+5)
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
                    print("\t\t [+] Outbound network event at hostname : {} ".format(computer_guids[guid]['hostname']))
                    print('\t\t\t {} : {} : {} : {} {}:{} -> {}:{}'.format(time,'outbound',computer_guids[guid]['hostname'],protocol,local_ip,local_port,remote_ip,remote_port))
                if direction == 'Incoming connection from':
                    print("\t\t [+] Inbound network event at hostname : {} ".format(computer_guids[guid]['hostname']))
                    print('\t\t\t {} : {} : {} :  {} {}:{} <- {}:{}'.format(time,'inbound',computer_guids[guid]['hostname'], protocol,local_ip,local_port,remote_ip,remote_port))
            if event_type == 'DFC Threat Detected':
                network_info = event['network_info']
                local_ip = network_info['local_ip']
                local_port = network_info['local_port']
                remote_ip = network_info['remote_ip']
                remote_port = network_info['remote_port']
                print("\t\t [+] Device flow correlation network event at hostname : {} ".format(computer_guids[guid]['hostname']))
                print('\t\t\t {} : {} DFC: {}:{} - {}:{}'.format(time,computer_guids[guid]['hostname'],local_ip,local_port,remote_ip,remote_port))
                
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
                    print("\t\t [+] Outbound network event at hostname : {} ".format(computer_guids[guid]['hostname']))
                    print('\t\t\t {} : {} : {} {}:{} -> {}:{}'.format(time,computer_guids[guid]['hostname'], protocol,local_ip,local_port,remote_ip,remote_port))
                    print('\t\t\t {} : {} : DOMAIN: {} : URL: {}'.format(time,computer_guids[guid]['hostname'],str(extractDomainFromURL(dirty_url)).replace(".","[.]"),str(dirty_url).replace(".","[.]")))
                if direction == 'Incoming connection from':
                    print("\t\t [+] Inbound network event at hostname : {} ".format(computer_guids[guid]['hostname']))
                    print('\t\t\t {} : {}: {} {}:{} <- {}:{}'.format(time,computer_guids[guid]['hostname'],protocol,local_ip,local_port,remote_ip,remote_port))
    except: 
        # that shouldn't really happen however sometimes connectors give back 404 error. This is because data exist in timeline but connector appear to be dead?
        pass



# Validate a command line parameter was provided
if len(sys.argv) < 2:
    sys.exit('Usage: <config file.txt>\n %s' % sys.argv[0])

# Parse config to extract API keys
config = configparser.ConfigParser()
config.read(sys.argv[1])
client_id = config['settings']['client_id']
api_key = config['settings']['api_key']
domainIP = config['settings']['domainIP']

try:
    # Creat session object
    # http://docs.python-requests.org/en/master/user/advanced/
    # Using a session object gains efficiency when making multiple requests
    session = requests.Session()
    session.auth = (client_id, api_key)

    # Define URL for extraction of all computers
    computers_url='https://{}/v1/computers'.format(domainIP)
    # Define response object to extract all computers
    response = session.get(computers_url, verify=False)
    # Get headers from request
    headers=response.headers
    # Ensure we don't cross API limits, sleep if we are approaching close to limits
    if int(headers['X-RateLimit-Remaining']) < 10:
        timeout=int(headers['X-RateLimit-Reset'])
        time.sleep(timeout+5)
        
    # Decode first JSON response
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

    print('[+] Total computers found: {}'.format(len(computer_guids)))
    # Submit to execution queue
    for guid in computer_guids:
        executor.submit(searchConnections,guid)
        

finally:
    gc.collect()