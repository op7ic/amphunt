# This script is based on https://github.com/CiscoSecurity/amp-04-check-sha256-execution
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

client_id = 'XXXXXXXXXXXXXXXXXXXXXX'# INSERT YOU API KEY
api_key = 'XXXXXXXXXXXXXXXXXXXXXX'# INSERT YOU API KEY
domainIP = 'XXX.XXX.XXX.XXX' # INSERT YOUR DOMAIN NAME/HOSTNAME WHERE AMP EXISTS


# Validate a command line parameter was provided
if len(sys.argv) < 2:
    sys.exit('Usage:\n %s hashfile.txt' % sys.argv[0])

# Store the command line parameter
sha256hashfile = sys.argv[1]

try:
    fp = open(sha256hashfile,'r')
    for sha256hash in fp.readlines():
        print("\n[+] Hunting for hash: {}".format(sha256hash))
		# Containers for output
        computer_guids = {}
        parent_to = {}
        direct_commands = {'process_names':set(), 'commands':set()}

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
            print("[+] Sleeping {} seconds to ensure reset clock works".format(int(headers['X-RateLimit-Reset'])))
            time.sleep(int(headers['X-RateLimit-Reset'])+5)
		# Decode JSON response
        response_json = response.json()

		# Name data section of JSON
        data = response_json['data']
		# Store unique connector GUIDs and hostnames
        for entry in data:
            connector_guid = entry['connector_guid']
            hostname = entry['hostname']
            computer_guids.setdefault(connector_guid, {'hostname':hostname})
        print('\t[+] Computers found: {}'.format(len(computer_guids)))

        # Query trajectory for each GUID
        for guid in computer_guids:
            # Print the hostname and GUID that is about to be queried
            print('\n\t\t[+] Querying: {} - {}'.format(computer_guids[guid]['hostname'], guid))
            trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
            trajectory_response = session.get(trajectory_url, params=payload, verify=False)
            # Decode JSON response
            trajectory_response_json = trajectory_response.json()
            # Name events section of JSON
            try:
                events = trajectory_response_json['data']['events']
                # Parse trajectory events to find the network events
                for event in events:
                    time=event['date']
                    event_type = event['event_type']
                    if 'command_line' in str(event) and 'arguments' in str(event['command_line']) and 'Executed' in str(event_type):
                        arguments = event['command_line']['arguments']
                        file_sha256 = event['file']['identity']['sha256']
                        parent_sha256 = event['file']['parent']['identity']['sha256']
                        file_name = event['file']['file_name']
                        direct_commands['process_names'].add(file_name)
                        direct_commands['commands'].add(format_arguments(arguments))
                        print('\t\t [+] Child SHA256: {}'.format(file_sha256))
                        print('\t\t [+] {} : {} Process name: {} args: {}'.format(time,computer_guids[guid]['hostname'], file_name,format_arguments(arguments)))
                        
                    if 'file_name' in str(event) and 'command_line' not in str(event):
                        print("\t\t [-] CMD could not be retrieved from hostname: {}".format(computer_guids[guid]['hostname']))
                        print("\t\t\t [+] {} : {} File Path: {}".format(time,computer_guids[guid]['hostname'],event['file']['file_path']))
                        print("\t\t\t [+] {} : {} Parent SHA256: {}".format(time,computer_guids[guid]['hostname'],event['file']['parent']['identity']['sha256']))
            except:
                pass
finally:
    fp.close()

