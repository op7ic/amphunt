import asyncio
import random
import time
import requests
import sys
import configparser
import gc
from threading import Event


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


async def worker(name, queue,domainIP,session,computer_guids):
    while True:
        # Get a "work item" out of the queue.
        guidcode = await queue.get()
        # build trajectory
        trajectory_url = 'https://{}/v1/computers/{}/trajectory'.format(domainIP,guidcode)
        # request trajectory over the same session
        trajectory_response = session.get(trajectory_url, verify=False)
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
                else:
                    Event().wait(20)
                    #reply request
                    worker(name, queue,domainIP,session)
                    print("no proper, sleeping - either 503 or server closing connection")
            else:
                Event().wait(20)
                #reply request
                worker(name, queue,domainIP,session)
                print("no headers, sleeping - either 503 or server closing connection")
        else:
            Event().wait(20)
            #reply request
            worker(name, queue,domainIP,session)
            print("no headers, sleeping - either 503 or server closing connection")
                    
        # Define variables we want to track
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

        trajectory_response_json = trajectory_response.json()
        # check we got JSON
        if trajectory_response_json:
            # check we got events
            events = trajectory_response_json['data']['events']
            if events:
                for event in events:
                    event_type = event['event_type']
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
                
                print("{},{},{},{},{},{},{},{},{},{},{},{},{}".format(
                    guidcode,
                    computer_guids[guidcode]['hostname'],
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

        # Notify the queue that the "work item" has been processed.
        queue.task_done()




async def main():
    # Create a queue that we will use to store our "workload".
    queue = asyncio.Queue()


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
    print('guid,hostname,Vulnerable Application Detected,NFM,File Executed,File Created,File Moved,Threat Quarantined,Threat Detected,Quarantine Failure,Malicious Activity Detection,Execution Blocked,Executed malware') 
   
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
    # check if we correctly got headers
    if headers != None:
        # We stop on 45 due to number of threads working
        if 'X-RateLimit-Remaining' and 'X-RateLimit-Reset' in str(headers):
            if(int(headers['X-RateLimit-Remaining']) < 45):
                if(headers['Status'] == "200 OK"):
                    # We are close to the border, in theory 429 error code should never trigger if we capture this event
                    # For some reason simply using time.sleep does not work very well here
                    await Event().wait((int(headers['X-RateLimit-Reset'])+5))
                if(headers['Status'] == "429 Too Many Requests"):
                    # Triggered too many request, we need to sleep before it continues
                    # For some reason simply using time.sleep does not work very well here
                    await Event().wait((int(headers['X-RateLimit-Reset'])+5))
        elif '503 Service Unavailable' in str(headers):
            await Event().wait(20)
        else:
            await Event().wait(20)
    else:
        # we didn't get headers, sleep
       await Event().wait(20)

    print("no problem")
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
            if headers != None:
                # We stop on 45 due to number of threads working
                if 'X-RateLimit-Remaining' and 'X-RateLimit-Reset' in str(headers):
                    if(int(headers['X-RateLimit-Remaining']) < 45):
                        if(headers['Status'] == "200 OK"):
                            # We are close to the border, in theory 429 error code should never trigger if we capture this event
                            # For some reason simply using time.sleep does not work very well here
                            await Event().wait((int(headers['X-RateLimit-Reset'])+5))
                        if(headers['Status'] == "429 Too Many Requests"):
                            # Triggered too many request, we need to sleep before it continues
                            # For some reason simply using time.sleep does not work very well here
                            await Event().wait((int(headers['X-RateLimit-Reset'])+5))
                elif '503 Service Unavailable' in str(headers):
                    await Event().wait(20)
                else:
                    await Event().wait(20)
            else:
                # we didn't get headers, sleep
               await Event().wait(20)

            # Extract GUIDs
            response_json = response.json()
            extractGUID(response_json['data'])

    # Add elements to queue
    for guid in computer_guids:
        queue.put_nowait(guid)

    # Create three worker tasks to process the queue concurrently.
    tasks = []
    for i in range(7):
        task = asyncio.create_task(worker(f'worker-{i}', queue,domainIP,session,computer_guids))
        tasks.append(task)

    # Wait until the queue is fully processed.
    started_at = time.monotonic()
    await queue.join()
    total_slept_for = time.monotonic() - started_at

    # Cancel our worker tasks.
    for task in tasks:
        task.cancel()
    # Wait until all worker tasks are cancelled.
    await asyncio.gather(*tasks, return_exceptions=True)

    print('====')
    print(f'workers slept in parallel for {total_slept_for:.2f} seconds')


asyncio.run(main())