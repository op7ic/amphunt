# Based on https://github.com/CiscoSecurity/amp-04-check-sha256-execution
import sys
import requests
# Ignore insecure cert warnings (enable only if working with local certs)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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
		print("[+] Hunting for hash: {}".format(sha256hash))
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

		# Decode JSON response
        response_json = response.json()

		# Name data section of JSON
        data = response_json['data']

		# Store unique connector GUIDs and hostnames
        for entry in data:
            connector_guid = entry['connector_guid']
            hostname = entry['hostname']
            computer_guids.setdefault(connector_guid, {'hostname':hostname})
        print('Computers found: {}'.format(len(computer_guids)))

		# Query trajectory for each GUID
        for guid in computer_guids:

			# Print the hostname and GUID that is about to be queried
            print('[+] Querying: {} - {}'.format(computer_guids[guid]['hostname'], guid))
            trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
            trajectory_response = session.get(trajectory_url, params=payload, verify=False)

			# # Decode JSON response
            trajectory_response_json = trajectory_response.json()

			# Name events section of JSON
            events = trajectory_response_json['data']['events']

			# Parse trajectory events to find the network events
            for event in events:
                event_type = event['event_type']
                if 'command_line' in event and 'arguments' in event['command_line']:
                    arguments = event['command_line']['arguments']
                    file_sha256 = event['file']['identity']['sha256']
                    parent_sha256 = event['file']['parent']['identity']['sha256']
                    file_name = event['file']['file_name']
                    if file_sha256 == sha256hash.strip():
                        direct_commands['process_names'].add(file_name)
                        direct_commands['commands'].add(format_arguments(arguments))
						# print('Process name: {}'.format(file_name))
						# print('  ',format_arguments(arguments))
                    if parent_sha256 == sha256hash.strip():
                        child_file_name = event['file']['file_name']
                        parent_to.setdefault(child_file_name, [])
                        parent_to[child_file_name].append(arguments)
			print('\n[+] Process names observed for the SHA256:')
			for name in direct_commands['process_names']:
				print('  ', name)
			print('\n[+] Command line arguments observed:')
			for command  in direct_commands['commands']:
				print('  ', command)
        
        print('\n[+] This SHA256 was also the parent of {} processes'.format(len(parent_to)))
        for process in parent_to:
            print(process)
            for arguments in parent_to[process]:
                print('  ', format_arguments(arguments))

finally:
    fp.close()

