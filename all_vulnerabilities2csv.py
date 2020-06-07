import sys
import requests
import configparser
import time
import gc
from urllib.parse import urlparse

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

def extractDomainFromURL(url):
    """ Extract domain name from URL"""
    return urlparse(url).netloc

# Validate a command line parameter was provided
if len(sys.argv) < 2:
    sys.exit('Usage: <config file.txt>\n %s' % sys.argv[0])

# Parse config to extract API keys
config = configparser.ConfigParser()
config.read(sys.argv[1])
client_id = config['settings']['client_id']
api_key = config['settings']['api_key']
domainIP = config['settings']['domainIP']

# Store the command line parameter
remote_ips = {}

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

        # try:
        events = trajectory_response_json['data']['events']
        for event in events:
            event_type = event['event_type']
            time = event['date'] 
            CVSS_list=list()
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
        # except:
        #     pass
finally:
    gc.collect()