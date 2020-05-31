# This script is based on https://github.com/CiscoSecurity/amp-01-basics/blob/master/04_get_events.py
# This script is based on https://stackoverflow.com/questions/41180960/convert-nested-json-to-csv-file-in-python
import sys
import requests
import time
import csv
import gc

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


client_id = 'XXXXXXXXXXXXXXX'# INSERT YOU API KEY
api_key = 'XXXXXXXXXXXXXXX'# INSERT YOU API KEY
domainIP = 'XXXXXXXXXXXXXXX' # INSERT YOUR DOMAIN NAME/HOSTNAME WHERE AMP EXISTS

# Validate a command line parameter was provided
if len(sys.argv) < 2:
    sys.exit('Usage: <event id> <csv file to write>\n %s' % sys.argv[0])

# Store the command line parameter
searchEventId=sys.argv[1]
fileDump=sys.argv[2]
# Store GUIDs types
computer_guids = {}
objects_to_write = {}
header = {}
fieldnames = set()
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
        objects_to_write.setdefault(str(connector_guid+"+"+date),walk_json(entry))
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
            objects_to_write.setdefault(str(connector_guid+"+"+date),walk_json(entry))    
        else:
            pass

# Store headers
header_set = set()
# Basic dict structure so we can store data for CSV write
basic_dict = dict()
# Store list of dict objects to write back to CSV files
output_list = list()

# Enum list of uniq objects from events
for key in objects_to_write:
    # Reduce the tuple to unique objects which can be sorted later. TODO - write complete reduced object to CSV
    small_tuple = reduceTuple(objects_to_write[key])
    # Extract and store specific dictionary elements
    for z in small_tuple:
        # Strip and convert only first row (we don't care about additional fields, just want basic ones to show problems)
        basic_dict.update({z[0]: z[1]})
    # Write objects to list that we can use to flush down to csvz
    output_list.append(basic_dict)        

# Make sure all header fields are added
for d in output_list:
    # Sort out all headers so they match with whatever headers we get from API
    for list_keys in d.keys():
        header_set.add(list_keys)

# Final flush to final output   
f = open(fileDump, 'w')
with f:
    # Use DictWriter to write dictionary write list of objects to csv file
    writer = csv.DictWriter(f, fieldnames=sorted(header_set))    
    # Append Header
    writer.writeheader()
    # Enumerate list of objects returned
    for d in output_list:
        writer.writerow(d)
f.close()

print("[+] Dumped {} lines to {}".format(len(output_list),fileDump))
# Collect garbage
gc.collect()


