# This script is based on https://github.com/CiscoSecurity/amp-04-check-sha256-execution
import sys
import requests
import configparser
import time

# Ignore insecure cert warnings (enable only if working with onsite-amp deployments)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Containers for output
computer_guids = {}

def format_arguments(_arguments):
    """ If arguments are in a list join them as a single string"""
    if isinstance(_arguments, list):
        return ' '.join(_arguments)
    return _arguments

def extractGUID(data):
    """ Extract GUIDs from data structure and store them in computer_guids variable"""
    for entry in data:
        connector_guid = entry['connector_guid']
        hostname = entry['hostname']
        computer_guids.setdefault(connector_guid, {'hostname':hostname})

def checkAPITimeout(headers, request):
    """Ensure we don't cross API limits, sleep if we are approaching close to limits"""
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
    sys.exit('Usage:\n %s <config file> <hashfile.txt>' % sys.argv[0])
    
# Parse config to extract API keys
config = configparser.ConfigParser()
config.read(sys.argv[1])
client_id = config['settings']['client_id']
api_key = config['settings']['api_key']
domainIP = config['settings']['domainIP']

# Store the command line parameter
sha256hashfile = sys.argv[2]

try:
    fp = open(sha256hashfile,'r')
    for sha256hash in fp.readlines():
        print("\n[+] Hunting for hash: {}".format(sha256hash))

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
        # verify headers and response body for potential API limit problems
        checkAPITimeout(headers,response)

		# Decode JSON response
        response_json = response.json()
        # Extract GUIDs from first page
        extractGUID(response_json['data'])
        # Handle paginated pages and extract computer GUIDs
        if('next' in response_json['metadata']['links']):
            while 'next' in response_json['metadata']['links']:
                next_url = response_json['metadata']['links']['next']
                response = session.get(next_url)
                headers=response.headers
                # verify headers and response body for potential API limit problems
                checkAPITimeout(headers,response)
                # Extract
                response_json = response.json()
                extractGUID(response_json['data'])
            print('\t[+] Computers found: {}'.format(len(computer_guids)))

        # Query trajectory for each GUID
        for guid in computer_guids:
            # Print the hostname and GUID that is about to be queried
            print('\n\t\t[+] Querying: {} - {}'.format(computer_guids[guid]['hostname'], guid))
            trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
            trajectory_response = session.get(trajectory_url, params=payload, verify=False)
            headers=trajectory_response.headers
            # verify headers and response body for potential API limit problems
            checkAPITimeout(headers,trajectory_response)
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
                        print('\t\t [+] {} : {} Process name: {} ChildSHA256: {} Args: {}'.format(date,computer_guids[guid]['hostname'], file_name,file_sha256,format_arguments(arguments)))
            except:
                pass
finally:
    fp.close()
