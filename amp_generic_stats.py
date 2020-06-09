from concurrent.futures import ThreadPoolExecutor
from threading import BoundedSemaphore
import time
import sys
import requests
import configparser
import gc
import threading

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

class BoundedExecutor:
    """BoundedExecutor behaves as a ThreadPoolExecutor which will block on
    calls to submit() once the limit given as "bound" work items are queued for
    execution.
    :param bound: Integer - the maximum number of items in the work queue
    :param max_workers: Integer - the size of the thread pool
    https://www.bettercodebytes.com/theadpoolexecutor-with-a-bounded-queue-in-python/
    """
    def __init__(self, bound, max_workers):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.semaphore = BoundedSemaphore(bound + max_workers)

    """See concurrent.futures.Executor#submit"""
    def submit(self, fn, *args, **kwargs):
        self.semaphore.acquire()
        try:
            future = self.executor.submit(fn, *args, **kwargs)
        except:
            self.semaphore.release()
            raise
        else:
            future.add_done_callback(lambda x: self.semaphore.release())
            return future

    """See concurrent.futures.Executor#shutdown"""
    def shutdown(self, wait=True):
        self.executor.shutdown(wait)

def getStatsOut(guid):
    """ Function to perform lookup on specific event type"""
    # Extract trajectory of computers based on their guid
    trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guid)
    # Wait 90 seconds to return results therefore becoming a blocking
    # That said, no request should need 90 turnaround unless you query via satelite link
    trajectory_response = session.get(trajectory_url, verify=False,timeout=90)
    # Extract headers (these are also returned)
    headers=trajectory_response.headers
    # In theory we should never reach point this because job scheduler below should take care of measuring API consumption
    # If we do reach this, we can have multiple threads sleeping at the same time since they all hit the same function. That's OK
    # We stop on 45 due to number of threads working
    if(int(headers['X-RateLimit-Remaining']) < 45):
        if(headers['Status'] == "200 OK"):
            # We are close to the border, in theory 429 error code should never trigger if we capture this event
            time.sleep((int(headers['X-RateLimit-Reset'])+5))
        if(headers['Status'] == "429 Too Many Requests"):
            print("entered_sleep")
            # Triggered too many request, we need to sleep before it continues
            time.sleep((int(headers['X-RateLimit-Reset'])+5))

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
    # Attempt to get parse JSON response. 
    # Igonore errors since it would mean they simply don't fit in defintion below
    try:
        trajectory_response_json = trajectory_response.json()
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
            time,
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
    except:
        pass
    return headers


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
    if int(headers['X-RateLimit-Remaining']) < 45:
        time.sleep(int(headers['X-RateLimit-Reset'])+5)
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
            if int(headers['X-RateLimit-Remaining']) < 45:
                timeout=int(headers['X-RateLimit-Reset'])
                time.sleep(timeout+5)
            # Extract
            response_json = response.json()
            extractGUID(response_json['data'])
    # Executor with limit on the queue by number of GUIDs
    # Limit to 8 threads. Full size of queue is number of computer GUIDs + number of threads
    executor = BoundedExecutor(8, len(computer_guids))
    # Define counter so we can scan every n-th thread for API timeout
    count = 0
    for guid in computer_guids:
        # submit task in non-blocking mode
        future = executor.submit(getStatsOut,guid)
        count+=1
        # check every 4th thread
        if (count == 3):
            # .result() function will block thread and wait. so we check only every 4th thread to see if we are still ok to proceed
            headers=future.result()
            if 'X-RateLimit-Remaining' in str(headers):
                if(int(headers['X-RateLimit-Remaining']) < 45):
                    if(headers['Status'] == "200 OK"):
                        # We are close to the border, in theory 429 error code should never trigger if we capture this event
                        time.sleep((int(headers['X-RateLimit-Reset'])+5))
                    if(headers['Status'] == "429 Too Many Requests"):
                        # Triggered too many request, we need to sleep before it continues
                        time.sleep((int(headers['X-RateLimit-Reset'])+5))
            else:
                # Header object is wrong. This is likley 429 response so sleep extra 10 before moving on to next GUID object
                # In theory this shouldn't be reached unless threads somehow skip more than 45 requests
                time.sleep(10)
                continue
            # reset counter back to 0
            count=0

finally:
    # collect leftovers
    gc.collect()