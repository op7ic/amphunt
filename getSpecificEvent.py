# This script is based on https://github.com/CiscoSecurity/amp-01-basics/blob/master/04_get_events.py
# This script is based on https://stackoverflow.com/questions/41180960/convert-nested-json-to-csv-file-in-python
# This script is based on https://www.geeksforgeeks.org/python-convert-list-of-tuples-to-dictionary-value-lists/
import sys
import requests
import time
import csv
import gc
import configparser
from collections import defaultdict 
from operator import itemgetter 
from itertools import groupby 

# Ignore insecure cert warnings (enable only if working with onsite-amp deployments)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Get all leaves from JSON file so headers can be used for CSV
def get_leaves(item, key=None):
    """ Idea taken from https://stackoverflow.com/questions/41180960/convert-nested-json-to-csv-file-in-python """ 
    if isinstance(item, dict):
        leaves = []
        for i in item.keys():
            leaves.extend(get_leaves(item[i], i))
        return leaves
    elif isinstance(item, list):
        leaves = []
        for i in item:
            leaves.extend(get_leaves(i, key))
        return leaves
    else:
        return [(key, item)]

# Perfrom reduction on Tuple to ensure that single key is present with multiple values as opposed to multiple keys
def reduceTuple(input_list): 
    """ Idea taken from https://www.geeksforgeeks.org/python-group-tuples-in-list-with-same-first-value/ """ 
    out = {} 
    for elem in input_list: 
        try: 
            out[elem[0]].extend(elem[1:]) 
        except KeyError: 
            out[elem[0]] = list(elem) 

    return [tuple(values) for values in out.values()] 

# Walk and sort JSON
def walk_json(event):
    """ Walk JSON to determine sensible fields to extract """
    """ Idea taken from https://stackoverflow.com/questions/41180960/convert-nested-json-to-csv-file-in-python """ 
    # Extract headers from JSON object
    return sorted(get_leaves(event))

def returnDictFromTuple(tup):
    return dict((k, [v[1] for v in itr]) for k, itr in groupby(tup, itemgetter(0))) 


# Validate a command line parameter was provided
if len(sys.argv) < 2:
    sys.exit('Usage: <config file> <event id> <csv file to write>\n %s' % sys.argv[0])

config = configparser.ConfigParser()
config.read(sys.argv[1])
client_id = config['settings']['client_id']
api_key = config['settings']['api_key']
domainIP = config['settings']['domainIP']

# Store the command line parameter
searchEventId=sys.argv[2]
fileDump=sys.argv[3]

# Store GUIDs + other elements
computer_guids = {}
objects_to_write = dict()

# Creat session object
# http://docs.python-requests.org/en/master/user/advanced/
# Using a session object gains efficiency when making multiple requests
session = requests.Session()
session.auth = (client_id, api_key)

# Define URL and parameters
events = 'https://{}/v1/events?event_type[]={}'.format(domainIP,searchEventId)
# Query API
response_events = session.get(events, verify=False)

# Get Headers
headers=response_events.headers
# Ensure we don't cross API limits, sleep if we are approaching limits
if int(headers['X-RateLimit-Remaining']) < 10:
    print("[+] Sleeping {} seconds to ensure reset clock works".format(int(headers['X-RateLimit-Reset'])))
    time.sleep(int(headers['X-RateLimit-Reset'])+5)
# Attempt to get valid JSON object, pass on error 
try:
    # Decode JSON response
    response_event_json = response_events.json()
    # Name data section of JSON
    data = response_event_json['data']
    # Name total section of JSON
    total = response_event_json['metadata']['results']['total']    
except:
    pass

# Print total number of alerts in AMP console
print("[+] Total results: {}".format(total))
print("[+] Event Type: {} ".format(data[0]['event_type']))
# For each record entry, add hostname and GUID of system which matches with Event ID, discard anything else
for entry in data:
    if int(entry['event_type_id']) == int(searchEventId) and entry['event_type'] != "Install Started":
        connector_guid = entry['connector_guid']
        hostname = entry['computer']['hostname']
        computer_guids.setdefault(connector_guid, {'hostname':hostname})
        date=entry['date']
        # We save GUID + Date to make unique key in the dictionary
        objects_to_write.setdefault(str(connector_guid+"+"+date),reduceTuple(walk_json(entry)))
    else:
        pass

# If we encounter 500+ events, walk the subsequent pages, not split into separate function for simplicity
while 'next' in response_event_json['metadata']['links']:
    # Retrieve next URL link
    next_url = response_event_json['metadata']['links']['next']
    response_events = session.get(next_url,verify=False)
    response_event_json = response_events.json()
    # Ensure we don't cross API limits, sleep if we are approaching limits
    headers=response_events.headers
    if int(headers['X-RateLimit-Remaining']) < 10:
        print("[+] Sleeping {} seconds to ensure reset clock works".format(int(headers['X-RateLimit-Reset'])))
        time.sleep(int(headers['X-RateLimit-Reset'])+5)
        
    data = response_event_json['data']
    # For each record entry, add hostname and GUID of system which matches with Event ID, discard anything else
    for entry in data:
        if int(entry['event_type_id']) == int(searchEventId) and entry['event_type'] != "Install Started":
            connector_guid = entry['connector_guid']
            hostname = entry['computer']['hostname']
            date=entry['date']
            computer_guids.setdefault(connector_guid, {'hostname':hostname})
            # We save GUID + Date to make unique key in the dictionary
            objects_to_write.setdefault(str(connector_guid+"+"+date),reduceTuple(walk_json(entry)))
        else:
            pass

# Store headers
header_set = set()
# Store list of dict objects to write back to CSV files
output_list = list()

bs=dict()
# Assign values to keys
for key, values in objects_to_write.items():
    # Create new dict from tuples
    bs[key] = returnDictFromTuple(values)
    for list_keys in bs[key].keys():
        header_set.add(list_keys)
    output_list.append(bs)

# # Final flush to final output csv
f = open(fileDump, 'w')

with f:
    # Use DictWriter to write dictionary write list of objects to csv file
    writer = csv.DictWriter(f, fieldnames=header_set,restval="-")    
    # Append Header
    writer.writeheader()
    # Enumerate list of objects returned
    for k in bs.values():
        writer.writerow(k)


f.close()

print("[+] Dumped {} lines to {}".format(len(bs),fileDump))
# Collect garbage
gc.collect()

