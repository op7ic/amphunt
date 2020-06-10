# This script is based on https://github.com/CiscoSecurity/amp-04-sha256-to-network-connections/blob/master/sha256_to_network_connections.py
import sys
import requests
import configparser
import time
import gc
from threading import Event

# Ignore insecure cert warnings (enable only if working with onsite-amp deployments)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def extractGUID(data):
    """ Extract GUIDs from data structure and store them in computer_guids variable"""
    for entry in data:
        connector_guid = entry['connector_guid']
        hostname = entry['hostname']
        computer_guids.setdefault(connector_guid, {'hostname':hostname})


def trajectoryRequest(guid):
    """ re-issue trajectory request"""
    try:
        trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
        trajectory_response = session.get(trajectory_url, verify=False,timeout=90)
        if trajectory_response != None:
            # Extract headers (these are also returned)
            headers=trajectory_response.headers
            # check if we correctly got headers
            if headers != None:
                # If we do reach this, we can have multiple threads sleeping at the same time since they all hit the same function. That's OK
                # We stop on 45 due to number of threads working
                if 'X-RateLimit-Remaining' and 'X-RateLimit-Reset' in str(headers):
                    if(int(headers['X-RateLimit-Remaining']) < 45):
                        if(headers['Status'] == "200 OK"):
                            # We are close to the border, in theory 429 error code should never trigger if we capture this event
                            # For some reason simply using time.sleep does not work very well here
                            Event().wait((int(headers['X-RateLimit-Reset'])+5))
                        if(headers['Status'] == "429 Too Many Requests"):
                            # Triggered too many request, we need to sleep before it continues
                            # For some reason simply using time.sleep does not work very well here
                            Event().wait((int(headers['X-RateLimit-Reset'])+5))
                    else:
                        return headers
                elif '503 Service Unavailable' in str(headers):
                    # 503 sent back - server is starting to close
                    Event().wait(40)
                    trajectoryRequest(guid)
                    return "0"
                else:
                    #server closed this connection, wait 40 sec to see if we reopen
                    Event().wait(40)
                    # retry
                    trajectoryRequest(guid)
                    return "0"
            else:
                Event().wait(40)
                trajectoryRequest(guid)
                return "0"
    except KeyError:
        Event().wait(40)
        return "0"
    except:
        Event().wait(40)
        return "0"


# Validate a command line parameter was provided
if len(sys.argv) < 2:
    sys.exit('Usage: <config file.txt>\n %s' % sys.argv[0])

# Parse config to extract API keys
config = configparser.ConfigParser()
config.read(sys.argv[1])
client_id = config['settings']['client_id']
api_key = config['settings']['api_key']
domainIP = config['settings']['domainIP']

# Containers for output
computer_guids = {}

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
    if headers != None and 'X-RateLimit-Remaining' and 'X-RateLimit-Reset' in str(headers):
        if int(headers['X-RateLimit-Remaining']) < 20:
            # This is last one before it kicks in timeout
            if(headers['Status'] == "200 OK"):
                time.sleep((int(headers['X-RateLimit-Reset'])+5))
            if(headers['Status'] == "429 Too Many Requests"):
                # Triggered too many request, we need to sleep before it continues
                time.sleep((int(headers['X-RateLimit-Reset'])+5))
    else:
        #probably 503
        time.sleep(40)
        
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
            if headers != None and 'X-RateLimit-Remaining' and 'X-RateLimit-Reset' in str(headers):
                if int(headers['X-RateLimit-Remaining']) < 20:
                    # This is last one before it kicks in timeout
                    if(headers['Status'] == "200 OK"):
                        time.sleep((int(headers['X-RateLimit-Reset'])+5))
                    if(headers['Status'] == "429 Too Many Requests"):
                        # Triggered too many request, we need to sleep before it continues
                        time.sleep((int(headers['X-RateLimit-Reset'])+5))
            else:
                #probably 503 or server closed connection
                time.sleep(40)
            # Extract
            response_json = response.json()
            extractGUID(response_json['data'])

    print('[+] Total computers found: {}'.format(len(computer_guids)))

    for guid in computer_guids:
        print('\n\t[+] Querying: {} - {}'.format(computer_guids[guid]['hostname'], guid))
        trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
        trajectory_response = session.get(trajectory_url, verify=False,timeout=90)
        trajectory_response_json = trajectory_response.json()

        if trajectory_response:
            # Extract headers (these are also returned)
            headers=trajectory_response.headers
            # check if we correctly got headers
            if headers:
                # We stop on 45 due to number of threads working
                if 'X-RateLimit-Remaining' and 'X-RateLimit-Reset' in str(headers):
                    if(int(headers['X-RateLimit-Remaining']) < 45):
                        if(headers['Status'] == "200 OK"):
                            # We are close to the border, in theory 429 error code should never trigger if we capture this event
                            # For some reason simply using time.sleep does not work very well here
                            Event().wait((int(headers['X-RateLimit-Reset'])+5))
                        if(headers['Status'] == "429 Too Many Requests"):
                            # Triggered too many request, we need to sleep before it continues
                            # For some reason simply using time.sleep does not work very well here
                            Event().wait((int(headers['X-RateLimit-Reset'])+5))
                elif '503 Service Unavailable' in str(headers):
                    # We sleep - server sent 503 - probably thinking its DDOS. Sleep 40 before moving on 
                    Event().wait(40)
                    # re-issue the same trajectory request, hope for headers to come back
                    h = trajectoryRequest(guid)
                    # check if we got the right parameters in there
                    if h != "0" and 'X-RateLimit-Remaining' and 'X-RateLimit-Reset' in str(h):
                        headers=h
                    else:
                        headers="0"
                else:
                    # We also need to sleep - server closed connection
                    # Connection, closed. Similar headers to below:
                    """{'Cache-Control': 'no-cache', 'Connection': 'close', 'Content-Type': 'text/html'}"""
                    Event().wait(40)
                    h = trajectoryRequest(guid)
                    # check if we got the right parameters in there
                    if h != "0" and 'X-RateLimit-Remaining' and 'X-RateLimit-Reset' in str(h):
                        headers=h
                    else:
                        headers="0"

            events = trajectory_response_json['data']['events']
            if events != None:
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
                        if direction == 'Outgoing connection from' and remote_port == '445' or remote_port == '139':
                            print('\t\t\t {} : {} : {} : {} {}:{} -> {}:{}'.format(time,'outbound SMB',computer_guids[guid]['hostname'],protocol,local_ip,local_port,remote_ip,remote_port))
                        if direction == 'Incoming connection from' and local_port =='445' or remote_port =='139':
                            print('\t\t\t {} : {} : {} :  {} {}:{} <- {}:{}'.format(time,'inbound SMB',computer_guids[guid]['hostname'], protocol,local_ip,local_port,remote_ip,remote_port))
                        if direction == 'Outgoing connection from' and remote_port == '3389':
                            print('\t\t\t {} : {} : {} : {} {}:{} -> {}:{}'.format(time,'outbound RDP',computer_guids[guid]['hostname'],protocol,local_ip,local_port,remote_ip,remote_port))
                        if direction == 'Incoming connection from' and local_port == '3389':
                            print('\t\t\t {} : {} : {} :  {} {}:{} <- {}:{}'.format(time,'inbound RDP',computer_guids[guid]['hostname'], protocol,local_ip,local_port,remote_ip,remote_port))
                        if direction == 'Outgoing connection from' and remote_port == '5985':
                            print('\t\t\t {} : {} : {} : {} {}:{} -> {}:{}'.format(time,'outbound WINRM - HTTP',computer_guids[guid]['hostname'],protocol,local_ip,local_port,remote_ip,remote_port))
                        if direction == 'Incoming connection from' and local_port == '5985':
                            print('\t\t\t {} : {} : {} :  {} {}:{} <- {}:{}'.format(time,'inbound WINRM - HTTP',computer_guids[guid]['hostname'], protocol,local_ip,local_port,remote_ip,remote_port))
                        if direction == 'Outgoing connection from' and remote_port == '5986':
                            print('\t\t\t {} : {} : {} : {} {}:{} -> {}:{}'.format(time,'outbound WINRM - HTTPS',computer_guids[guid]['hostname'],protocol,local_ip,local_port,remote_ip,remote_port))
                        if direction == 'Incoming connection from' and local_port == '5986':
                            print('\t\t\t {} : {} : {} :  {} {}:{} <- {}:{}'.format(time,'inbound WINRM - HTTPS',computer_guids[guid]['hostname'], protocol,local_ip,local_port,remote_ip,remote_port))
                        if direction == 'Outgoing connection from' and remote_port == '135':
                            print('\t\t\t {} : {} : {} : {} {}:{} -> {}:{}'.format(time,'outbound WMIC/SC (RPC)',computer_guids[guid]['hostname'],protocol,local_ip,local_port,remote_ip,remote_port))
                        if direction == 'Incoming connection from' and local_port == '135':
                            print('\t\t\t {} : {} : {} :  {} {}:{} <- {}:{}'.format(time,'inbound WMIC/SC (RPC)',computer_guids[guid]['hostname'], protocol,local_ip,local_port,remote_ip,remote_port))
                        
        else:
            # events array not received - we just pass
            pass

finally:
    gc.collect()
    print("[+] Done")