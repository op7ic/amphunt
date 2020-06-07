import sys
import requests
import configparser
import time
import gc
from multiprocessing.pool import ThreadPool

# Ignore insecure cert warnings (enable only if working with onsite-amp deployments)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Containers for GUIDs
computer_guids = {}

def extractGUID(data):
    """ Extract GUIDs from data structure and store them in computer_guids variable"""
    for entry in data:
        connector_guid = entry['connector_guid']
        hostname = entry['hostname']
        computer_guids.setdefault(connector_guid, {'hostname':hostname})


# Validate a command line parameter was provided
if len(sys.argv) < 2:
    sys.exit('Usage: <config file.txt>\n %s' % sys.argv[0])

# Parse config to extract API keys
config = configparser.ConfigParser()
config.read(sys.argv[1])
client_id = config['settings']['client_id']
api_key = config['settings']['api_key']
domainIP = config['settings']['domainIP']

#Print header for CSV 
print('date,guid,hostname,Vulnerable Application Detected,NFM,File Executed,File Created,File Moved,Threat Quarantined,Threat Detected,Quarantine Failure,Malicious Activity Detection,Execution Blocked,Executed malware') 

try:
    # Creat session object
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
    if int(headers['X-RateLimit-Remaining']) < 10:
        time.sleep(int(headers['X-RateLimit-Reset'])+5)
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
            if int(headers['X-RateLimit-Remaining']) < 10:
                timeout=int(headers['X-RateLimit-Reset'])
                time.sleep(timeout+5)
            # Extract
            response_json = response.json()
            extractGUID(response_json['data'])
            
    for guid in computer_guids:
        # Extract trajectory of computers based on their guid
        trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
        trajectory_response = session.get(trajectory_url, verify=False)
        trajectory_response_json = trajectory_response.json()
        # define variables which will be applicable per each GUID
        vulnerable=0
        nfm=0
        executed=0
        create=0
        moved=0
        threat_q=0
        threat_d=0
        quarantine_fail=0
        malicious_activity=0
        exec_blocked=0
        exec_malware=0
        # try:
        events = trajectory_response_json['data']['events']
        for event in events:
            event_type = event['event_type']
            time = event['date'] 

            #filter by specific event type  
            if event_type == 'Vulnerable Application Detected':
                vulnerable+=1
            if event_type == 'NFM':
                nfm+=1
            if event_type == 'Executed by':
                executed+=1
            if event_type == 'Created by':
                create+=1
            if event_type == 'Moved by':
                moved+=1
            if event_type == 'Threat Quarantined':
                threat_q+=1
            if event_type == 'Threat Detected':
                threat_d+=1
            if event_type == 'Quarantine Failure':
                quarantine_fail+=1
            if event_type == 'Malicious Activity Detection':
                malicious_activity+=1
            if event_type == 'Execution Blocked':
                exec_blocked+=1
            if event_type == 'Executed Malware':
                exec_malware+=1
        print("{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format(
            date,
            guid,
            computer_guids[guid]['hostname'],
            vulnerable,
            nfm,
            executed,
            create,
            moved,
            threat_q,
            threat_d,
            quarantine_fail,
            malicious_activity,
            exec_blocked,
            exec_malware))
finally:
    gc.collect()