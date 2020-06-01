# This script is based on https://github.com/CiscoSecurity/amp-04-check-sha256-execution
import sys
import requests
import time
import configparser
import csv

# Ignore insecure cert warnings (enable only if working with onsite-amp deployments without valid certificate)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def format_arguments(_arguments):
    """ If arguments are in a list join them as a single string"""
    if isinstance(_arguments, list):
        return ' '.join(_arguments)
    return _arguments

# Validate a command line parameter was provided
if len(sys.argv) < 2:
    sys.exit('Usage:\n %s <config.txt> <hashfile.txt>' % sys.argv[0])

#Parse config
config = configparser.ConfigParser()
config.read(sys.argv[1])
client_id = config['settings']['client_id']
api_key = config['settings']['api_key']
domainIP = config['settings']['domainIP']

# Store the command line parameter
sha256hashfile = sys.argv[2]

# Store objects:
computer_guids = {}
objects_to_write = {}

#Print header for CSV 
print('date,guid,hostname,sha256,Parent sha256,file_name,arguments')
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
                
        # Decode first JSON response to determine if we got more pages to search
        response_event_json = response.json()
        # Name data section of JSON
        data = response_event_json['data']
        # Name total section of JSON
        total = response_event_json['metadata']['results']['total']
		# Store unique connector GUIDs and hostnames on first, unpaged result
        for entry in data:
            connector_guid = entry['connector_guid']
            hostname = entry['hostname']
            computer_guids.setdefault(connector_guid, {'hostname':hostname})

        # Handle pagination, add matching GUIDs to global array
        while 'next' in response_event_json['metadata']['links']:
            # Retrieve next URL link
            next_url = response_event_json['metadata']['links']['next']
            response_events = session.get(next_url,verify=False)
            response_event_json_paged = response_events.json()

            # Ensure we don't cross API limits, sleep if we are approaching limits
            headers=response_events.headers
            if int(headers['X-RateLimit-Remaining']) < 10:
                time.sleep(int(headers['X-RateLimit-Reset'])+5)

            # Handle data object from next pages, append connector data to existing object
            data_paged = response_event_json_paged['data']
            # Store unique connector GUIDs and hostnames from next pages
            for entry_paged in data_paged:
                connector_guid = entry_paged['connector_guid']
                hostname = entry_paged['hostname']
                computer_guids.setdefault(connector_guid, {'hostname':hostname})

        # Finally, for each GUID we match the args with trajectory (trajectory is limited to last 500 events however)
        for guid in computer_guids:
            trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
            trajectory_response = session.get(trajectory_url, params=payload, verify=False)
            headers=trajectory_response.headers
            # Handle potential API limits
            if int(headers['X-RateLimit-Remaining']) < 10:
                time.sleep(int(headers['X-RateLimit-Reset'])+5)
            trajectory_response_json = trajectory_response.json()
            #   Name events section of JSON
            try:
                # only focus on actual events, ignore DFC and other type of telemetry (hence pass for exception)
                events = trajectory_response_json['data']['events']
                # Parse trajectory events to find the network events
                for event in events:
                    timestamp=event['date']
                    event_type = event['event_type']
                    if 'command_line' in str(event) and 'arguments' in str(event['command_line']) and 'Executed' in str(event_type):
                        arguments = event['command_line']['arguments']
                        file_sha256 = event['file']['identity']['sha256']
                        parent_sha256 = event['file']['parent']['identity']['sha256']
                        file_name = event['file']['file_name']
                        direct_commands['process_names'].add(file_name)
                        direct_commands['commands'].add(format_arguments(arguments))
                        print("{},{},{},{},{},{},{}".format(timestamp,
                            guid,
                            computer_guids[guid]['hostname'],
                            file_sha256,
                            parent_sha256,
                            file_name,
                            format_arguments(arguments)))

                    if 'file_name' in str(event) and 'command_line' not in str(event):
                        file_sha256 = event['file']['identity']['sha256']
                        parent_sha256 = event['file']['parent']['identity']['sha256']
                        file_name = event['file']['file_name']
                        print("{},{},{},{},{},{},{}".format(timestamp,
                            guid,
                            computer_guids[guid]['hostname'],
                            file_sha256,
                            parent_sha256,
                            file_name,
                            "-")) # this line won't have command line so final argument is always "-"
            except:
                 pass

finally:
    fp.close()
