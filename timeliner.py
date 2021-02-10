import sys
import requests
import configparser
import argparse
import time
import os


#####################################################################################
# HELPERS
#####################################################################################

# Ignore insecure cert warnings (enable only if working with onsite-amp deployments)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Container for host GUIDs and commands
computer_guids = {}
direct_commands = {'process_names':set(), 'commands':set()}

# Ensure that file path is actually valid, to be used by ArgumentParser 'type' option
def validate_file(f):
    if not os.path.exists(f):
        # Raise exception if specified path does not exist
        raise argparse.ArgumentTypeError("Path {0} does not exist".format(f))
    return f

def format_arguments(_arguments):
    """ If arguments are in a list join them as a single string"""
    if isinstance(_arguments, list):
        return ' '.join(_arguments)
    return _arguments


# Quick validation of key elements before they are parsed
def validate_dict_element(dictionary, fields):
    try:
        x = dictionary[fields]
        return True
    except KeyError:
        return False

def extractGUID(data):
    """ Extract GUIDs from data structure and store them in computer_guids variable"""
    for entry in data:
        connector_guid = entry['connector_guid']
        hostname = entry['hostname']
        computer_guids.setdefault(connector_guid, {'hostname':hostname})

def checkAPITimeout(headers, request):
    """Ensure we don't cross API limits, sleep if we are approaching close to limits"""
    if str(request.status_code) == '200':
        # Extract headers (these are also returned)
        headers=request.headers
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
    elif str(request.status_code) == '404':
        # 404 - this could mean event timeline or event does no longer exists
        time.sleep(45)
        pass
    elif str(request.status_code) == '503':
        # server sarted to block us
        time.sleep(90)
        pass
    else:
        # in any other case, sleep
        time.sleep(90)
        pass

#####################################################################################
# MAIN
#####################################################################################

def main():
    # Parse arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--config", dest="config_path", required=True, help="Path to config file", type=validate_file, metavar="FILE")
    ap.add_argument("-o", "--output", dest="outout_folder", required=True, help="Path to output folder", type=validate_file)
    args = ap.parse_args()

    # Parse config to extract API keys
    config = configparser.ConfigParser()
    config.read(args.config_path)
    client_id = config['settings']['client_id']
    api_key = config['settings']['api_key']
    domainIP = config['settings']['domainIP']

    try:
    	# Creat session object
    	# http://docs.python-requests.org/en/master/user/advanced/
    	# Using a session object gains efficiency when making multiple requests
        session = requests.Session()
        session.auth = (client_id, api_key)

    	# Define URL and parameters
        computers_url='https://{}/v1/computers'.format(domainIP)

    	# Query API
        response = session.get(computers_url, verify=False)
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
            # try:
            trajectory_response = session.get(trajectory_url, verify=False)
            headers=trajectory_response.headers
            # verify headers and response body for potential API limit problems
            checkAPITimeout(headers,trajectory_response)
            # Decode JSON response
            trajectory_response_json = trajectory_response.json()
            # Name events section of JSON
            
            events = trajectory_response_json['data']['events']
            # define name for our output file as '[hostname]_[guid].txt'
            filename = os.path.join(args.outout_folder,"{}_{}.txt".format(computer_guids[guid]['hostname'],guid))
            # Parse trajectory events to find events (max 500 per host)
            f = open(filename, "w")
            try:
                for event in events:
                    checkAPITimeout(headers,trajectory_response)
                    timestamp=event['date']
                    event_type = event['event_type']
                    # Threat is detected, major difference is lack of file type in this event so we need separate handling
                    if event_type == "Threat Detected":
                        # Search for any command lines executed
                        if 'command_line' in str(event) and 'arguments' in str(event['command_line']) :
                            if(validate_dict_element(event['file'],'parent')):
                                arguments = event['command_line']['arguments']
                                file_sha256 = event['file']['identity']['sha256']
                                parent_sha256 = event['file']['parent']['identity']['sha256']
                                file_name = event['file']['file_name']
                                direct_commands['process_names'].add(file_name)
                                direct_commands['commands'].add(format_arguments(arguments))
                                f.write('{} : {} : {} Parent SHA256 : {} File SHA256: {} Process name: {} Arguments: {} Disposition: {}\n'.format(timestamp,
                                    computer_guids[guid]['hostname'],
                                    event_type,
                                    parent_sha256,
                                    file_sha256, 
                                    file_name,
                                    format_arguments(arguments),
                                    event['file']['disposition']))
                            else:
                                arguments = event['command_line']['arguments']
                                file_sha256 = event['file']['identity']['sha256']
                                file_name = event['file']['file_name']
                                direct_commands['process_names'].add(file_name)
                                direct_commands['commands'].add(format_arguments(arguments))
                                f.write('{} : {} : {} File SHA256: {} Process name: {} Arguments: {} Disposition: {}\n'.format(timestamp,
                                    computer_guids[guid]['hostname'],
                                    event_type,
                                    file_sha256, 
                                    file_name,
                                    format_arguments(arguments),
                                    event['file']['disposition']))

                        #Search for any binaries that do not have argument
                        if 'file_name' in str(event) and 'command_line' not in str(event):
                            if(validate_dict_element(event['file'],'parent')):  
                                f.write("{} : {} : {} Parent SHA256: {} File Path: {} File SHA256: {} Disposition: {}\n".format(timestamp,
                                    computer_guids[guid]['hostname'],
                                    event_type,
                                    event['file']['parent']['identity']['sha256'],
                                    event['file']['file_path'],
                                    event['file']['identity']['sha256'],
                                    event['file']['disposition']))
                            else:
                                f.write("{} : {} : {} File Path: {} File SHA256: {} Disposition: {}\n".format(timestamp,
                                    computer_guids[guid]['hostname'],
                                    event_type,
                                    event['file']['file_path'],
                                    event['file']['identity']['sha256'],
                                    event['file']['disposition']))

                    # Define event types for file action
                    exec_strings = {'Moved by', # File was moved 
                                    'Malicious Activity Detection',  # Malicious activity
                                    'Created by', # File was created
                                    'Executed by' # File was executed
                                    }

                    if event_type in exec_strings:
                        # Search for any command lines executed
                        if 'command_line' in str(event) and 'arguments' in str(event['command_line']) :
                            if(validate_dict_element(event['file'],'parent')):
                                arguments = event['command_line']['arguments']
                                file_sha256 = event['file']['identity']['sha256']
                                parent_sha256 = event['file']['parent']['identity']['sha256']
                                file_name = event['file']['file_name']
                                direct_commands['process_names'].add(file_name)
                                direct_commands['commands'].add(format_arguments(arguments))
                                f.write('{} : {} : {} Parent SHA256 : {} File SHA256: {} Process name: {} Arguments: {} File Type: {} Disposition: {}\n'.format(timestamp,
                                    computer_guids[guid]['hostname'],
                                    event_type,
                                    parent_sha256,
                                    file_sha256, 
                                    file_name,
                                    format_arguments(arguments),
                                    event['file']['file_type'],
                                    event['file']['disposition']))
                            else:
                                arguments = event['command_line']['arguments']
                                file_sha256 = event['file']['identity']['sha256']
                                file_name = event['file']['file_name']
                                direct_commands['process_names'].add(file_name)
                                direct_commands['commands'].add(format_arguments(arguments))
                                f.write('{} : {} : {} File SHA256: {} Process name: {} Arguments: {} File Type: {} Disposition: {}\n'.format(timestamp,
                                    computer_guids[guid]['hostname'],
                                    event_type,
                                    file_sha256, 
                                    file_name,
                                    format_arguments(arguments),
                                    event['file']['file_type'],
                                    event['file']['disposition']))

                        #Search for any binaries that do not have argument
                        if 'file_name' in str(event) and 'command_line' not in str(event):
                            if(validate_dict_element(event['file'],'parent')):
                                f.write("{} : {} : {} Parent SHA256: {} File Path: {} File SHA256: {} File Type: {} Disposition: {}\n".format(timestamp,
                                    computer_guids[guid]['hostname'],
                                    event_type,
                                    event['file']['parent']['identity']['sha256'],
                                    event['file']['file_path'],
                                    event['file']['identity']['sha256'],
                                    event['file']['file_type'],
                                    event['file']['disposition']))
                            else:
                                f.write("{} : {} : {} File Path: {} File SHA256: {} File Type: {} Disposition: {}\n".format(timestamp,
                                    computer_guids[guid]['hostname'],
                                    event_type,
                                    event['file']['file_path'],
                                    event['file']['identity']['sha256'],
                                    event['file']['file_type'],
                                    event['file']['disposition']))

                    # Search for network-type events
                    elif event_type == 'NFM':
                        network_info = event['network_info']
                        protocol = network_info['nfm']['protocol']
                        local_ip = network_info['local_ip']
                        local_port = network_info['local_port']
                        remote_ip = network_info['remote_ip']
                        remote_port = network_info['remote_port']
                        direction = network_info['nfm']['direction']
                        if direction == 'Outgoing connection from':
                            f.write('{} : {} : {} : {} {}:{} -> {}:{}\n'.format(timestamp,
                                computer_guids[guid]['hostname'],
                                'outbound',
                                protocol,
                                local_ip,
                                local_port,
                                remote_ip,
                                remote_port))
                        if direction == 'Incoming connection from':
                            f.write('{} : {} : {} :  {} {}:{} <- {}:{}\n'.format(timestamp,
                                computer_guids[guid]['hostname'],
                                'inbound', 
                                protocol,
                                local_ip,
                                local_port,
                                remote_ip,
                                remote_port))
                    
                    elif event_type == 'DFC Threat Detected':
                        network_info = event['network_info']
                        local_ip = network_info['local_ip']
                        local_port = network_info['local_port']
                        remote_ip = network_info['remote_ip']
                        remote_port = network_info['remote_port']
                        f.write('{} : {} DFC: {}:{} - {}:{}\n'.format(timestamp,
                            computer_guids[guid]['hostname'],
                            local_ip,
                            local_port,
                            remote_ip,
                            remote_port))
                        
                    elif event_type == 'NFM' and 'dirty_url' in str(event):
                        network_info = event['network_info']
                        dirty_url= event['network_info']['dirty_url']
                        protocol = network_info['nfm']['protocol']
                        local_ip = network_info['local_ip']
                        local_port = network_info['local_port']
                        remote_ip = network_info['remote_ip']
                        remote_port = network_info['remote_port']
                        direction = network_info['nfm']['direction']
                        if direction == 'Outgoing connection from':
                            f.write('{} : {} : {} : {} {}:{} -> {}:{} URL: {} DOMAIN: {}\n'.format(timestamp,
                                computer_guids[guid]['hostname'],
                                'outbound',
                                protocol,
                                local_ip,
                                local_port,
                                remote_ip,
                                remote_port,
                                str(dirty_url).replace(".","[.]"),
                                str(extractDomainFromURL(dirty_url)).replace(".","[.]")))
                        if direction == 'Incoming connection from':
                            f.write('{} : {} : {} :  {} {}:{} <- {}:{}\n'.format(timestamp,
                                computer_guids[guid]['hostname'],
                                'inbound', 
                                protocol,
                                local_ip,
                                local_port,
                                remote_ip,
                                remote_port))
                    elif event_type == 'Vulnerable Application Detected' or 'Policy Update':
                        # pass this for now
                        pass
                    elif event_type == 'Quarantine Failure':
                        f.write('{} : {} : Event: {} Severity: {} Disposition: {} File SHA256: {}\n'.format(
                                timestamp,
                                computer_guids[guid]['hostname'],
                                event_type,
                                event['severity'],
                                event['file']['disposition'],
                                event['file']['identity']['sha256']))
                    else:
                        print(event)
                # close stream
                f.close()
            except:
                # server disconnected us
                time.sleep(90)
                pass
    except:
    	pass
    finally:
        print("[+] Done")

if __name__ == "__main__":
    main()