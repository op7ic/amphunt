import sys
import requests
import configparser
import time
import gc

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
    checkAPITimeout(headers, response)
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
            checkAPITimeout(headers, response)
            # Extract
            response_json = response.json()
            extractGUID(response_json['data'])
            
    for guid in computer_guids:
        # Extract trajectory of computers based on their guid
        trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
        trajectory_response = session.get(trajectory_url, verify=False)
        trajectory_response_json = trajectory_response.json()
        headers=trajectory_response.headers
        # Ensure we don't cross API limits, sleep if we are approaching close to limits
        checkAPITimeout(headers, trajectory_response)
        try:
            events = trajectory_response_json['data']['events']
            for event in events:
                event_type = event['event_type']
                timestamp = event['date'] 
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
                        timestamp,
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
finally:
    gc.collect()