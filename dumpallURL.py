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

def extractDomainFromURL(url):
    """ Extract domain name from URL"""
    return urlparse(url).netloc

def extractGUID(data):
    """ Extract GUIDs from data structure and store them in computer_guids variable"""
    for entry in data:
        connector_guid = entry['connector_guid']
        hostname = entry['hostname']
        computer_guids.setdefault(connector_guid, {'hostname':hostname})

def checkAPITimeout(headers, response):
    """Ensure we don't cross API limits, sleep if we are approaching limits"""
    if response:
        # Extract headers (these are also returned)
        headers=response.headers
        # check if we correctly got headers
        if headers:
            # We stop on 45 due to number of threads working
            if 'X-RateLimit-Remaining' and 'X-RateLimit-Reset' in str(headers):
                if(int(headers['X-RateLimit-Remaining']) < 45):
                    if(headers['Status'] == "200 OK"):
                        # We are close to the border, in theory 429 error code should never trigger if we capture this event
                        # For some reason simply using time.sleep does not work very well here
                        time.sleep((int(headers['X-RateLimit-Reset'])+5))
                    if(headers['Status'] == "429 Too Many Requests"):
                        # Triggered too many request, we need to sleep before it continues
                        # For some reason simply using time.sleep does not work very well here
                        time.sleep((int(headers['X-RateLimit-Reset'])+5))
            elif '503 Service Unavailable' in str(headers):
                time.sleep(60)
            else: # we got some new error
                time.sleep(45)
        else:
            # no headers, request probably failed
            time.sleep(45)
    else: 
        print("[-] We are not getting response from server. Quiting")
        sys.exit(1)



# Validate a command line parameter was provided
if len(sys.argv) < 2:
    sys.exit('Usage: <config file.txt>\n %s' % sys.argv[0])

# Parse config to extract API keys
config = configparser.ConfigParser()
config.read(sys.argv[1])
client_id = config['settings']['client_id']
api_key = config['settings']['api_key']
domainIP = config['settings']['domainIP']

# Store the command line parameter
computer_guids = {}

try:

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
    checkAPITimeout(headers, response)
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
            checkAPITimeout(headers, response)
            # Extract
            response_json = response.json()
            extractGUID(response_json['data'])


    print('[+] Total computers found: {}'.format(len(computer_guids)))
    for guid in computer_guids:
        print('\n\t[+] Querying: {} - {}'.format(computer_guids[guid]['hostname'], guid))
        trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
        trajectory_response = session.get(trajectory_url, verify=False)
        trajectory_response_json = trajectory_response.json()
        headers=trajectory_response.headers
        # Ensure we don't cross API limits, sleep if we are approaching close to limits
        checkAPITimeout(headers, trajectory_response)
        try:
            events = trajectory_response_json['data']['events']
            for event in events:
                event_type = event['event_type']
                timestamp = event['date']
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
                        print("\t\t [+] Outbound URL request at hostname: {}".format(computer_guids[guid]['hostname']))
                        print('\t\t\t {} Host: {} URL: {} DOMAIN: {}'.format(timestamp,computer_guids[guid]['hostname'], dirty_url,extractDomainFromURL(dirty_url)))
                    if direction == 'Incoming connection from':
                        print("\t\t [+] Inbound URL request at hostname: {}".format(computer_guids[guid]['hostname']))
                        print('\t\t\t {} Host: {} URL: {} DOMAIN: {}'.format(timestamp,computer_guids[guid]['hostname'], dirty_url,extractDomainFromURL(dirty_url)))
        except:
            pass

finally:
    gc.collect()
    print("[+] Done")