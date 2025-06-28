#!/usr/bin/env python3
"""
Script Name: getSpecificEvent.py
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt

getSpecificEvent.py - Extract and export specific event types

This script searches for and exports all events of a specific type across
your AMP environment. Supports complex event data extraction and CSV export.

Usage:
	python getSpecificEvent.py -c/--config <config_file> <event_id> <output.csv>
"""

import sys
import argparse
import csv
from collections import defaultdict
from itertools import groupby
from operator import itemgetter
from amp_client import AMPClient, Config
from amp_client.models import EventType


def get_leaves(item, key=None):
	"""Extract all leaf nodes from nested dictionary/list structure"""
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


def reduce_tuple(input_list):
	"""Reduce tuples to ensure single key with multiple values"""
	out = {}
	for elem in input_list:
		try:
			out[elem[0]].extend(elem[1:])
		except KeyError:
			out[elem[0]] = list(elem)
	return [tuple(values) for values in out.values()]


def walk_json(event):
	"""Walk JSON to extract all fields in sorted order"""
	return sorted(get_leaves(event))


def dict_from_tuple(tup):
	"""Convert tuple list to dictionary"""
	return dict((k, [v[1] for v in itr]) for k, itr in groupby(tup, itemgetter(0)))


def main():
	parser = argparse.ArgumentParser(description='Extract specific event types from AMP')
	parser.add_argument('-c', '--config', required=True, help='Configuration file path')
	parser.add_argument('event_id', help='Event type ID to search for')
	parser.add_argument('output', help='Output CSV file path')
	parser.add_argument('--limit', type=int, help='Limit number of events to process')
	args = parser.parse_args()

	# Load configuration
	config = Config.from_file(args.config)

	# Validate event ID
	try:
		event_id = int(args.event_id)
	except ValueError:
		sys.exit(f"Error: Event ID must be a number, got: {args.event_id}")

	# Create client
	with AMPClient(config) as client:
		print(f"[+] Searching for event type ID: {event_id}")

		# Get event type name if possible
		try:
			event_type_name = EventType.get_name(event_id)
			print(f"[+] Event Type: {event_type_name}")
		except:
			event_type_name = f"Event ID {event_id}"
			print(f"[+] Event Type: Unknown (ID: {event_id})")

		# Collect all events
		all_events = []
		objects_to_write = {}
		header_set = set()

		# Search for events
		event_count = 0
		for event in client.events.search_by_type(event_id):
			# Skip "Install Started" events as they're typically not useful
			if event.event_type == "Install Started":
				continue

			# Create unique key for deduplication
			unique_key = f"{event.connector_guid}+{event.date}"

			# Extract all fields from event
			event_dict = event.__dict__
			flattened = reduce_tuple(walk_json(event_dict))
			objects_to_write[unique_key] = flattened

			event_count += 1
			if args.limit and event_count >= args.limit:
				print(f"[+] Reached limit of {args.limit} events")
				break

			# Progress indicator
			if event_count % 100 == 0:
				print(f"[+] Processed {event_count} events...")

		print(f"[+] Total results: {event_count}")

		if event_count == 0:
			print(f"[-] No events found for event ID {event_id}")
			return

		# Process collected events for CSV export
		processed_events = {}
		for key, values in objects_to_write.items():
			processed_events[key] = dict_from_tuple(values)
			# Collect all possible headers
			for field_key in processed_events[key].keys():
				header_set.add(field_key)

		# Write to CSV
		print(f"[+] Writing {len(processed_events)} unique events to {args.output}")

		with open(args.output, 'w', newline='', encoding='utf-8') as f:
			writer = csv.DictWriter(f, fieldnames=sorted(header_set), restval="-")
			writer.writeheader()

			for event_data in processed_events.values():
				# Flatten lists to strings for CSV
				row = {}
				for key, value in event_data.items():
					if isinstance(value, list):
						# Join list values with semicolon
						row[key] = ';'.join(str(v) for v in value)
					else:
						row[key] = value
				writer.writerow(row)

		print(f"[+] Dumped {len(processed_events)} lines to {args.output}")
		print("[+] Done")


if __name__ == "__main__":
	main()