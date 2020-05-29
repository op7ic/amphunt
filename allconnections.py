# This script is based on https://github.com/CiscoSecurity/amp-04-sha256-to-network-connections/blob/master/sha256_to_network_connections.py
import sys
import requests

# Ignore insecure cert warnings (enable only if working with onsite-amp deployments)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import time

def format_arguments(_arguments):
    """ If arguments are in a list join them as a single string"""
    if isinstance(_arguments, list):
        return ' '.join(_arguments)
    return _arguments

client_id = 'XXXXXXXXXXXXXXXXX'# INSERT YOU API KEY
api_key = 'XXXXXXXXXXXXXXXXX'# INSERT YOU API KEY
domainIP = 'XXXXXXXXXXXXXXXXX' # INSERT YOUR DOMAIN NAME/HOSTNAME WHERE AMP EXISTS

# Validate a command line parameter was provided
if len(sys.argv) < 1:
    sys.exit('Usage:\n %s' % sys.argv[0])

# Store the command line parameter
remote_ips = {}

try:
	# Containers for output
    computer_guids = {}
    parent_to = {}
    direct_commands = {'process_names':set(), 'commands':set()}

	# Creat session object
	# http://docs.python-requests.org/en/master/user/advanced/
	# Using a session object gains efficiency when making multiple requests
    session = requests.Session()
    session.auth = (client_id, api_key)

    #Define URL for extraction of all computers
    computers_url='https://{}/v1/computers'.format(domainIP)
    response = session.get(computers_url, verify=False)
    # Get Headers
    headers=response.headers
    # Ensure we don't cross API limits, sleep if we are approaching close to limits
    if int(headers['X-RateLimit-Remaining']) < 10:
        print("[+] Sleeping {} seconds to ensure reset clock works".format(int(headers['X-RateLimit-Reset'])))
        time.sleep(int(headers['X-RateLimit-Reset'])+5)
    # Decode JSON response
    response_json = response.json()
    data = response_json['data']
    for entry in data:
        connector_guid = entry['connector_guid']
        hostname = entry['hostname']
        computer_guids.setdefault(connector_guid, {'hostname':hostname})

    print('[+] Total computers found: {}'.format(len(computer_guids)))
    for guid in computer_guids:
        print('\n\t[+] Querying: {} - {}'.format(computer_guids[guid]['hostname'], guid))
        trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
        try:
            trajectory_response = session.get(trajectory_url, verify=False)
            trajectory_response_json = trajectory_response.json()
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
                    if remote_ip not in remote_ips:
                        remote_ips[remote_ip] = {'ports':[]}
                    if remote_port not in remote_ips[remote_ip]['ports']:
                        remote_ips[remote_ip]['ports'].append(remote_port)
                    if direction == 'Outgoing connection from':
                        print("\t\t [+] Outbound network event at hostname : {} ".format(computer_guids[guid]['hostname']))
                        print('\t\t\t {} : {} : {} {}:{} -> {}:{}'.format(time,hostname,protocol,local_ip,local_port,remote_ip,remote_port))
                    if direction == 'Incoming connection from':
                        print("\t\t [+] Inbound network event at hostname : {} ".format(computer_guids[guid]['hostname']))
                        print('\t\t\t {} : {} :  {} {}:{} <- {}:{}'.format(time,hostname, protocol,local_ip,local_port,remote_ip,remote_port))
                if event_type == 'DFC Threat Detected':
                    network_info = event['network_info']
                    local_ip = network_info['local_ip']
                    local_port = network_info['local_port']
                    remote_ip = network_info['remote_ip']
                    remote_port = network_info['remote_port']
                    if remote_ip not in remote_ips:
                        remote_ips[remote_ip] = {'ports':[]}
                    if remote_port not in remote_ips[remote_ip]['ports']:
                        remote_ips[remote_ip]['ports'].append(remote_port)
                    print("\t\t [+] Device flow correlation network event at hostname : {} ".format(computer_guids[guid]['hostname']))
                    print('\t\t\t {} : {} DFC: {}:{} - {}:{}'.format(time,hostname,local_ip,local_port,remote_ip,remote_port))
                    
                if event_type == 'NFM' and 'dirty_url' in str(event):
                    network_info = event['network_info']
                    dirty_url= event['network_info']['dirty_url']
                    protocol = network_info['nfm']['protocol']
                    local_ip = network_info['local_ip']
                    local_port = network_info['local_port']
                    remote_ip = network_info['remote_ip']
                    remote_port = network_info['remote_port']
                    direction = network_info['nfm']['direction']
                    if remote_ip not in remote_ips:
                        remote_ips[remote_ip] = {'ports':[]}
                    if remote_port not in remote_ips[remote_ip]['ports']:
                        remote_ips[remote_ip]['ports'].append(remote_port)
                    if direction == 'Outgoing connection from':
                        print("\t\t [+] Outbound network event at hostname : {} ".format(computer_guids[guid]['hostname']))
                        print('\t\t\t {} : {} : {} {}:{} -> {}:{}'.format(time,hostname, protocol,local_ip,local_port,remote_ip,remote_port))
                        print('\t\t\t {} : {} : URL: {}'.format(time,hostname,dirty_url))
                    if direction == 'Incoming connection from':
                        print("\t\t [+] Inbound network event at hostname : {} ".format(computer_guids[guid]['hostname']))
                        print('\t\t\t {} : {}: {} {}:{} <- {}:{}'.format(time,hostname,protocol,local_ip,local_port,remote_ip,remote_port))
        except:
            pass


finally:
    print("[+] Done")