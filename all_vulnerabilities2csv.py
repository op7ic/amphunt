import sys
import requests
import configparser
import time
import gc
import multiprocessing
import logging
from concurrent.futures import ThreadPoolExecutor
import threading

# Ignore insecure cert warnings (enable only if working with onsite-amp deployments)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Containers for GUIDs
computer_guids = {}
# Create threadpool instance with 4 workers
executor = ThreadPoolExecutor(max_workers=4)

def vulSearch(guid):
    """ Function to perform lookup on specific event type"""
    # Extract trajectory of computers based on their guid
    trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
    trajectory_response = session.get(trajectory_url, verify=False)
    trajectory_response_json = trajectory_response.json()
    headers=trajectory_response.headers
    try:
        events = trajectory_response_json['data']['events']
        for event in events:
            event_type = event['event_type']
            time = event['date'] 
            # a list to store CVSS values
            CVSS_list=list()
            # a list to store all CVE numbers
            allCVE=list()
            #filter by specific event type  
            if event_type == 'Vulnerable Application Detected':
                severity=event['severity']
                outdateFile=event['file']['file_name']
                sha256outdateFile=event['file']['identity']['sha256']
                # this can be an array so instead of printing it all, we simply take the first vulnerability
                oldestVulnerability=event['vulnerabilities'][0]
                # loop over all CVSS scores and take average
                for j in (event['vulnerabilities']):
                    CVSS_list.append(float(j['score']))
                    allCVE.append(j['cve'])
                # get rounded CVSS value    
                roundedCVSS=round(sum(CVSS_list)/len(CVSS_list))
                glob_cve=("|".join(allCVE))
                # final printout of all vulnerabilities
                print("{},{},{},{},{},{},{},{},{},{},{},{},{},{}".format(
                    time,
                    guid,
                    computer_guids[guid]['hostname'],
                    'Vulnerable Application',
                    severity,
                    outdateFile,
                    sha256outdateFile,
                    oldestVulnerability['name'],
                    oldestVulnerability['cve'],
                    oldestVulnerability['version'],
                    oldestVulnerability['score'],
                    roundedCVSS,
                    glob_cve,
                    oldestVulnerability['url']))
    except:
        pass
    return headers
        
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
print('date,guid,hostname,type,severity,file_name,file_sha256,product_name,oldest_CVE,oldest_version_impacted,oldest_cvss_score,average_cvss,all_CVE,oldest_reference_url') 

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
    if int(headers['X-RateLimit-Remaining']) < 20:
        # This is last one before it kicks in timeout
        if(headers['Status'] == "200 OK"):
            time.sleep((int(headers['X-RateLimit-Reset'])+5))
            #re-auth 
            session = requests.Session()
            session.auth = (client_id, api_key)
        if(headers['Status'] == "429 Too Many Requests"):
            # Triggered too many request, we need to sleep before it continues
            time.sleep((int(headers['X-RateLimit-Reset'])+5))
            #re-auth but sleep before that
            session = requests.Session()
            session.auth = (client_id, api_key)
    # Decode JSON response
    response_json = response.json()
    #Page 1 extract all GUIDs
    extractGUID(response_json['data'])

    # Handle paginated pages and extract computer GUIDs
    if('next' in response_json['metadata']['links']):
        while 'next' in response_json['metadata']['links']:
            next_url = response_json['metadata']['links']['next']
            response = session.get(next_url, verify=False)
            headers=response.headers
            # Ensure we don't cross API limits, sleep if we are approaching close to limits
            if int(headers['X-RateLimit-Remaining']) < 20:
                # This is last one before it kicks in timeout
                if(headers['Status'] == "200 OK"):
                    time.sleep((int(headers['X-RateLimit-Reset'])+5))
                if(headers['Status'] == "429 Too Many Requests"):
                    # Triggered too many request, we need to sleep before it continues
                    time.sleep((int(headers['X-RateLimit-Reset'])+5))
            # Extract
            response_json = response.json()
            extractGUID(response_json['data'])
    # add tasks to executor, invoke 4 workers at the time to increase speed
    for guid in computer_guids:
        future=executor.submit(vulSearch,guid)
        thread_array=future.result()
        if(int(thread_array['X-RateLimit-Remaining']) < 20):
            if(thread_array['Status'] == "200 OK"):
                # We are close to the border, in theory 429 error code should never trigger
                time.sleep((int(thread_array['X-RateLimit-Reset'])+5))
            if(thread_array['Status'] == "429 Too Many Requests"):
                # Triggered too many request, we need to sleep before it continues
                time.sleep((int(thread_array['X-RateLimit-Reset'])+5))

    
finally:
    gc.collect()