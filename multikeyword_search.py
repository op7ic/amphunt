# This script is based on https://github.com/CiscoSecurity/amp-04-check-sha256-execution
import sys
import requests
import configparser
import time
from urllib.parse import urlparse
import gc

# Ignore insecure cert warnings (enable only if working with onsite-amp deployments)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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

def extractDomainFromURL(url):
    """ Extract domain name from URL"""
    return urlparse(url).netloc

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
    sys.exit('Usage:\n %s <config file> <hashfile.txt>' % sys.argv[0])
    
# Parse config to extract API keys
config = configparser.ConfigParser()
config.read(sys.argv[1])
client_id = config['settings']['client_id']
api_key = config['settings']['api_key']
domainIP = config['settings']['domainIP']

# Store the command line parameter
keywordsFile = sys.argv[2]

try:
    fp = open(keywordsFile,'r')
    for searchterm in fp.readlines():
        print("\n[+] Hunting for keyword: {}".format(searchterm))
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
        payload = {'q': searchterm.strip()}

        # Query API
        response = session.get(activity_url, params=payload, verify=False)
        # Get Headers
        headers=response.headers

        # Ensure we don't cross API limits, sleep if we are approaching close to limits
        checkAPITimeout(headers, response)
        # Decode JSON response
        response_json = response.json()
        # Extract GUIDs
        extractGUID(response_json['data'])
        # Handle paginated pages and extract computer GUIDs
        if('next' in response_json['metadata']['links']):
            while 'next' in response_json['metadata']['links']:
                checkAPITimeout(headers, response)
                next_url = response_json['metadata']['links']['next']
                response = session.get(next_url)
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
            # Ensure we don't cross API limits, sleep if we are approaching close to limits
            checkAPITimeout(headers, trajectory_response)
            # Decode JSON response
            trajectory_response_json = trajectory_response.json()
            # Name events section of JSON
            try:

                events = trajectory_response_json['data']['events']

                # Parse trajectory events to find the network events
                for event in events:
                    time=event['date']
                    event_type = event['event_type']
                    # Search for executed
                    if 'Moved by' in str(event_type):
                        # Search for any command lines executed
                        if 'command_line' in str(event) and 'arguments' in str(event['command_line']) :
                            arguments = event['command_line']['arguments']
                            file_sha256 = event['file']['identity']['sha256']
                            parent_sha256 = event['file']['parent']['identity']['sha256']
                            file_name = event['file']['file_name']
                            direct_commands['process_names'].add(file_name)
                            direct_commands['commands'].add(format_arguments(arguments))
                            print('\t\t [+] Process SHA256 : {} Child SHA256: {}'.format(parent_sha256,file_sha256))
                            print('\t\t [+] {} : {} Process name: {} args: {}'.format(time,computer_guids[guid]['hostname'], file_name,format_arguments(arguments)))
                        #Search for any binaries
                        if 'file_name' in str(event) and 'command_line' not in str(event):
                            print("\t\t [-] CMD could not be retrieved from hostname: {}".format(computer_guids[guid]['hostname']))
                            print("\t\t\t [+] {} : {} File Path: {}".format(time,computer_guids[guid]['hostname'],event['file']['file_path']))
                            print("\t\t\t [+] {} : {} Parent SHA256: {}".format(time,computer_guids[guid]['hostname'],event['file']['parent']['identity']['sha256']))

                    if 'Threat Detected' in str(event_type):
                        # Search for any command lines executed
                        if 'command_line' in str(event) and 'arguments' in str(event['command_line']) :
                            arguments = event['command_line']['arguments']
                            file_sha256 = event['file']['identity']['sha256']
                            parent_sha256 = event['file']['parent']['identity']['sha256']
                            file_name = event['file']['file_name']
                            direct_commands['process_names'].add(file_name)
                            direct_commands['commands'].add(format_arguments(arguments))
                            print('\t\t [+] Process SHA256 : {} Child SHA256: {}'.format(parent_sha256,file_sha256))
                            print('\t\t [+] {} : {} Process name: {} args: {}'.format(time,computer_guids[guid]['hostname'], file_name,format_arguments(arguments)))
                        #Search for any binaries
                        if 'file_name' in str(event) and 'command_line' not in str(event):
                            print("\t\t [-] CMD could not be retrieved from hostname: {}".format(computer_guids[guid]['hostname']))
                            print("\t\t\t [+] {} : {} File Path: {}".format(time,computer_guids[guid]['hostname'],event['file']['file_path']))
                            if 'parent' in str(event):
                                print("\t\t\t [+] {} : {} Parent SHA256: {}".format(time,computer_guids[guid]['hostname'],event['file']['parent']['identity']['sha256']))
                            else:
                                pass

                    if 'Malicious Activity Detection' in str(event_type):
                        # Search for any command lines executed
                        if 'command_line' in str(event) and 'arguments' in str(event['command_line']) :
                            arguments = event['command_line']['arguments']
                            file_sha256 = event['file']['identity']['sha256']
                            parent_sha256 = event['file']['parent']['identity']['sha256']
                            file_name = event['file']['file_name']
                            direct_commands['process_names'].add(file_name)
                            direct_commands['commands'].add(format_arguments(arguments))
                            print('\t\t [+] Process SHA256 : {} Child SHA256: {}'.format(parent_sha256,file_sha256))
                            print('\t\t [+] {} : {} Process name: {} args: {}'.format(time,computer_guids[guid]['hostname'], file_name,format_arguments(arguments)))
                        #Search for any binaries
                        if 'file_name' in str(event) and 'command_line' not in str(event):
                            print("\t\t [-] CMD could not be retrieved from hostname: {}".format(computer_guids[guid]['hostname']))
                            print("\t\t\t [+] {} : {} File Path: {}".format(time,computer_guids[guid]['hostname'],event['file']['file_path']))
                            print("\t\t\t [+] {} : {} Parent SHA256: {}".format(time,computer_guids[guid]['hostname'],event['file']['parent']['identity']['sha256']))

                    if 'Created' in str(event_type):
                        # Search for any command lines executed
                        if 'command_line' in str(event) and 'arguments' in str(event['command_line']) :
                            arguments = event['command_line']['arguments']
                            file_sha256 = event['file']['identity']['sha256']
                            parent_sha256 = event['file']['parent']['identity']['sha256']
                            file_name = event['file']['file_name']
                            direct_commands['process_names'].add(file_name)
                            direct_commands['commands'].add(format_arguments(arguments))
                            print('\t\t [+] Process SHA256 : {} Child SHA256: {}'.format(parent_sha256,file_sha256))
                            print('\t\t [+] {} : {} Process name: {} args: {}'.format(time,computer_guids[guid]['hostname'], file_name,format_arguments(arguments)))
                        #Search for any binaries
                        if 'file_name' in str(event) and 'command_line' not in str(event):
                            print("\t\t [-] CMD could not be retrieved from hostname: {}".format(computer_guids[guid]['hostname']))
                            print("\t\t\t [+] {} : {} File Path: {}".format(time,computer_guids[guid]['hostname'],event['file']['file_path']))
                            print("\t\t\t [+] {} : {} Parent SHA256: {}".format(time,computer_guids[guid]['hostname'],event['file']['parent']['identity']['sha256']))


                    if 'Executed' in str(event_type):
                        # Search for any command lines executed
                        if 'command_line' in str(event) and 'arguments' in str(event['command_line']) :
                            arguments = event['command_line']['arguments']
                            file_sha256 = event['file']['identity']['sha256']
                            parent_sha256 = event['file']['parent']['identity']['sha256']
                            file_name = event['file']['file_name']
                            direct_commands['process_names'].add(file_name)
                            direct_commands['commands'].add(format_arguments(arguments))
                            print('\t\t [+] Process SHA256 : {} Child SHA256: {}'.format(parent_sha256,file_sha256))
                            print('\t\t [+] {} : {} Process name: {} args: {}'.format(time,computer_guids[guid]['hostname'], file_name,format_arguments(arguments)))
                        #Search for any binaries
                        if 'file_name' in str(event) and 'command_line' not in str(event):
                            print("\t\t [-] CMD could not be retrieved from hostname: {}".format(computer_guids[guid]['hostname']))
                            print("\t\t\t [+] {} : {} File Path: {}".format(time,computer_guids[guid]['hostname'],event['file']['file_path']))
                            print("\t\t\t [+] {} : {} Parent SHA256: {}".format(time,computer_guids[guid]['hostname'],event['file']['parent']['identity']['sha256']))

                    # Search for network-type events
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
            except:# sometimes we get 404 on connector (it no longer exist but data is still in the activity)
                pass
     
finally:
    fp.close()
    gc.collect()
