#!/usr/bin/env python3
"""
Script Name: hash2processarg.py
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt

hash2processarg.py - Find process arguments for specific file hashes

This script searches for process execution events with command-line arguments
for files matching the provided SHA256 hashes. Useful for understanding how
malware was executed and what parameters were used.

Usage:
	python hash2processarg.py -c/--config <config_file> <hashfile.txt> [--csv output.csv]
"""

import sys
import argparse
from collections import defaultdict
from amp_client import AMPClient, Config
from amp_client.utils import CSVExporter


def format_arguments(arguments):
	"""Format command line arguments for display"""
	if isinstance(arguments, list):
		return ' '.join(arguments)
	return arguments or ''


def process_hash(client, sha256):
	"""Process a single hash and find associated process executions"""
	print(f"\n[+] Hunting for hash: {sha256}")

	# Track unique commands and computers
	computers_found = {}
	unique_commands = defaultdict(set)  # command -> set of computers
	all_events = []

	# Search for activity
	print("\t[+] Searching for file activity...")
	for activity in client.activities.search_by_sha256(sha256):
		guid = activity.get('connector_guid')
		hostname = activity.get('hostname', 'Unknown')
		if guid not in computers_found:
			computers_found[guid] = hostname

	print(f'\t[+] Computers found: {len(computers_found)}')

	# Query trajectory for each computer
	for guid, hostname in computers_found.items():
		print(f'\n\t\t[+] Querying: {hostname} - {guid}')

		try:
			# Get trajectory filtered by the hash
			trajectory = client.computers.get_trajectory(guid, q=sha256)

			# Process events looking for executions
			execution_events = 0
			for event in trajectory.events:
				# Check if this event involves our target file
				if event.file and event.file_sha256 == sha256:
					# Look for execution events with command line
					if 'command_line' in event.__dict__ and event.__dict__.get('command_line'):
						cmd_line = event.__dict__['command_line']
						if 'arguments' in cmd_line:
							arguments = format_arguments(cmd_line['arguments'])
							file_name = event.file.get('file_name', 'unknown')
							parent_info = event.file.get('parent', {})
							parent_sha = parent_info.get('identity', {}).get('sha256', 'unknown')
							parent_name = parent_info.get('file_name', 'unknown')
							timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")

							# Track unique commands
							cmd_key = f"{file_name} {arguments}"
							unique_commands[cmd_key].add(hostname)

							# Display
							print(f'\t\t [+] Process SHA256 : {parent_sha} Child SHA256: {sha256}')
							print(f'\t\t [+] {timestamp} : {hostname} Process name: {file_name} args: {arguments}')

							all_events.append({
								'timestamp': timestamp,
								'hostname': hostname,
								'hash': sha256,
								'file_name': file_name,
								'arguments': arguments,
								'parent_sha256': parent_sha,
								'parent_name': parent_name,
								'file_path': event.file.get('file_path', ''),
								'event_type': event.event_type
							})
							execution_events += 1

					# Also check for file events without command line
					elif event.file.get('file_name') and event.event_type in ['Executed by', 'Created by', 'Moved by']:
						file_name = event.file.get('file_name', 'unknown')
						file_path = event.file.get('file_path', '')
						parent_info = event.file.get('parent', {})
						parent_sha = parent_info.get('identity', {}).get('sha256', 'unknown')
						timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")

						print(f"\t\t [-] CMD could not be retrieved from hostname: {hostname}")
						print(f"\t\t\t [+] {timestamp} : {hostname} File Path: {file_path}")
						print(f"\t\t\t [+] {timestamp} : {hostname} Parent SHA256: {parent_sha}")

						all_events.append({
							'timestamp': timestamp,
							'hostname': hostname,
							'hash': sha256,
							'file_name': file_name,
							'arguments': '[No arguments captured]',
							'parent_sha256': parent_sha,
							'parent_name': parent_info.get('file_name', 'unknown'),
							'file_path': file_path,
							'event_type': event.event_type
						})
						execution_events += 1

			if execution_events == 0:
				print(f"\t\t [-] No execution events found for this hash")

		except Exception as e:
			print(f"\t\t [!] Error processing {hostname}: {e}")
			continue

	# Summary of unique commands
	if unique_commands:
		print(f"\n\t[+] Unique command lines for {sha256}:")
		for cmd, hosts in sorted(unique_commands.items()):
			print(f"\t\t{cmd}")
			print(f"\t\t  Executed on: {', '.join(sorted(hosts))}")

	return all_events


def main():
	parser = argparse.ArgumentParser(description='Find process arguments for file hashes')
	parser.add_argument('-c', '--config', required=True, help='Configuration file path')
	parser.add_argument('hashfile', help='File containing SHA256 hashes (one per line)')
	parser.add_argument('--csv', help='Export results to CSV file')
	args = parser.parse_args()

	# Load configuration
	config = Config.from_file(args.config)

	# Read hashes from file
	try:
		with open(args.hashfile, 'r') as f:
			hashes = [line.strip() for line in f if line.strip()]
	except Exception as e:
		sys.exit(f"Error reading hash file: {e}")

	if not hashes:
		sys.exit("No hashes found in input file")

	print(f"[+] Loaded {len(hashes)} hashes to search")

	# Create client
	with AMPClient(config) as client:
		all_results = []

		# Process each hash
		for sha256 in hashes:
			events = process_hash(client, sha256)
			all_results.extend(events)

		# Export to CSV if requested
		if args.csv and all_results:
			print(f'\n[+] Exporting {len(all_results)} events to {args.csv}...')

			# Convert to format for CSVExporter
			export_events = []
			for event in all_results:
				export_events.append({
					'date': event['timestamp'],
					'hostname': event['hostname'],
					'event_type': event['event_type'],
					'file_sha256': event['hash'],
					'file_name': event['file_name'],
					'file_path': event['file_path'],
					'arguments': event['arguments'],
					'parent_sha256': event['parent_sha256'],
					'parent_name': event['parent_name']
				})

			CSVExporter.export_events(
				export_events,
				args.csv,
				fields=['date', 'hostname', 'event_type', 'file_sha256', 'file_name', 
						'file_path', 'arguments', 'parent_sha256', 'parent_name']
			)
			print(f'[+] CSV export complete: {args.csv}')

		print("\n[+] Done")


if __name__ == "__main__":
	main()