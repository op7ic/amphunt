#!/usr/bin/env python3
"""
Script Name: multikeyword_search.py
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt

multikeyword_search.py - Search for multiple keywords across AMP environment

This script searches for multiple keywords/indicators (filenames, hashes, etc.)
across all computers, showing file executions, network connections, and threat events.

Usage:
	python multikeyword_search.py -c/--config <config_file> <keywords.txt> [--csv output.csv]
"""

import sys
import argparse
from collections import defaultdict
from amp_client import AMPClient, Config
from amp_client.utils import NetworkEventFormatter, FileEventFormatter, CSVExporter, OutputFormatter


def format_arguments(arguments):
	"""Format command line arguments for display"""
	if isinstance(arguments, list):
		return ' '.join(arguments)
	return arguments or ''


def process_keyword(client, keyword):
	"""Process a single keyword search"""
	print(f"\n[+] Hunting for keyword: {keyword}")

	# Track findings
	computers_found = {}
	unique_processes = defaultdict(set)  # process -> set of computers
	unique_commands = defaultdict(set)   # command -> set of computers
	all_events = []

	# Search for activity
	for activity in client.activities.search(keyword):
		guid = activity.get('connector_guid')
		hostname = activity.get('hostname', 'Unknown')
		if guid not in computers_found:
			computers_found[guid] = hostname

	print(f'\t[+] Computers found: {len(computers_found)}')

	# Query trajectory for each computer
	for guid, hostname in computers_found.items():
		print(f'\n\t\t[+] Querying: {hostname} - {guid}')

		try:
			# Get trajectory filtered by keyword
			trajectory = client.computers.get_trajectory(guid, q=keyword)

			# Process events
			for event in trajectory.events:
				timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")

				# Handle various event types that indicate file activity
				if event.event_type in ['Moved by', 'Threat Detected', 'Malicious Activity Detection', 
									   'Created by', 'Executed by']:

					# Process events with command line
					if hasattr(event, 'command_line') and event.command_line:
						cmd_line = event.command_line
						if 'arguments' in cmd_line:
							arguments = format_arguments(cmd_line['arguments'])
							file_info = event.file or {}
							file_name = file_info.get('file_name', 'unknown')
							file_sha256 = file_info.get('identity', {}).get('sha256', 'unknown')
							parent_info = file_info.get('parent', {})
							parent_sha256 = parent_info.get('identity', {}).get('sha256', 'unknown')

							# Track unique items
							unique_processes[file_name].add(hostname)
							unique_commands[format_arguments(arguments)].add(hostname)

							print(f'\t\t [+] Process SHA256 : {parent_sha256} Child SHA256: {file_sha256}')
							print(f'\t\t [+] {timestamp} : {hostname} Process name: {file_name} args: {arguments}')

							all_events.append({
								'timestamp': timestamp,
								'hostname': hostname,
								'keyword': keyword,
								'event_type': event.event_type,
								'file_name': file_name,
								'file_sha256': file_sha256,
								'arguments': arguments,
								'parent_sha256': parent_sha256,
								'file_path': file_info.get('file_path', ''),
								'type': 'execution'
							})

					# Process events without command line
					elif event.file and event.file.get('file_name'):
						file_info = event.file
						file_path = file_info.get('file_path', '')
						parent_info = file_info.get('parent', {})
						parent_sha256 = parent_info.get('identity', {}).get('sha256', 'unknown')

						print(f"\t\t [-] CMD could not be retrieved from hostname: {hostname}")
						print(f"\t\t\t [+] {timestamp} : {hostname} File Path: {file_path}")
						if parent_sha256 != 'unknown':
							print(f"\t\t\t [+] {timestamp} : {hostname} Parent SHA256: {parent_sha256}")

						all_events.append({
							'timestamp': timestamp,
							'hostname': hostname,
							'keyword': keyword,
							'event_type': event.event_type,
							'file_name': file_info.get('file_name', 'unknown'),
							'file_sha256': file_info.get('identity', {}).get('sha256', 'unknown'),
							'arguments': '[No arguments captured]',
							'parent_sha256': parent_sha256,
							'file_path': file_path,
							'type': 'file_activity'
						})

				# Handle network events
				elif event.event_type == 'NFM' and event.network_info:
					details = event.network_info
					direction = details.get('nfm', {}).get('direction', '')

					if 'Outgoing' in direction:
						print(f"\t\t [+] Outbound network event at hostname : {hostname}")
						connection = NetworkEventFormatter.format_connection(
							{'network_info': details}, sanitize=False
						)
						print(f'\t\t\t {timestamp} : outbound : {hostname} : {connection}')
					elif 'Incoming' in direction:
						print(f"\t\t [+] Inbound network event at hostname : {hostname}")
						connection = NetworkEventFormatter.format_connection(
							{'network_info': details}, sanitize=False
						)
						print(f'\t\t\t {timestamp} : inbound : {hostname} : {connection}')

					# Handle URL events
					if 'dirty_url' in details:
						url = details['dirty_url']
						domain = OutputFormatter.extract_domain(url)
						print(f'\t\t\t {timestamp} : {hostname} : DOMAIN: {OutputFormatter.sanitize_url(domain)} : URL: {OutputFormatter.sanitize_url(url)}')

					all_events.append({
						'timestamp': timestamp,
						'hostname': hostname,
						'keyword': keyword,
						'event_type': 'Network Connection',
						'file_name': '',
						'file_sha256': '',
						'arguments': connection,
						'parent_sha256': '',
						'file_path': details.get('dirty_url', ''),
						'type': 'network'
					})

				# Handle DFC Threat events
				elif event.event_type == 'DFC Threat Detected' and event.network_info:
					details = event.network_info
					print(f"\t\t [+] Device flow correlation network event at hostname : {hostname}")
					print(f'\t\t\t {timestamp} : {hostname} DFC: '
						  f'{details.get("local_ip")}:{details.get("local_port")} - '
						  f'{details.get("remote_ip")}:{details.get("remote_port")}')

					all_events.append({
						'timestamp': timestamp,
						'hostname': hostname,
						'keyword': keyword,
						'event_type': 'DFC Threat Detected',
						'file_name': '',
						'file_sha256': '',
						'arguments': f'DFC: {details.get("local_ip")}:{details.get("local_port")} - '
									f'{details.get("remote_ip")}:{details.get("remote_port")}',
						'parent_sha256': '',
						'file_path': '',
						'type': 'threat'
					})

		except Exception as e:
			print(f"\t\t [!] Error processing {hostname}: {e}")
			continue

	return all_events


def main():
	parser = argparse.ArgumentParser(description='Search for multiple keywords in AMP')
	parser.add_argument('-c', '--config', required=True, help='Configuration file path')
	parser.add_argument('keywords', help='File containing keywords (one per line)')
	parser.add_argument('--csv', help='Export results to CSV file')
	args = parser.parse_args()

	# Load configuration
	config = Config.from_file(args.config)

	# Read keywords from file
	try:
		with open(args.keywords, 'r') as f:
			keywords = [line.strip() for line in f if line.strip()]
	except Exception as e:
		sys.exit(f"Error reading keywords file: {e}")

	if not keywords:
		sys.exit("No keywords found in input file")

	print(f"[+] Loaded {len(keywords)} keywords to search")

	# Create client
	with AMPClient(config) as client:
		all_results = []

		# Process each keyword
		for keyword in keywords:
			events = process_keyword(client, keyword)
			all_results.extend(events)

		# Summary statistics
		if all_results:
			print(f"\n[+] Summary:")
			print(f"\tTotal events found: {len(all_results)}")

			# Events by type
			events_by_type = defaultdict(int)
			for event in all_results:
				events_by_type[event['type']] += 1

			print("\n\tEvents by category:")
			for event_type, count in sorted(events_by_type.items()):
				print(f"\t  {event_type}: {count}")

		# Export to CSV if requested
		if args.csv and all_results:
			print(f'\n[+] Exporting {len(all_results)} events to {args.csv}...')

			# Convert to format for CSVExporter
			export_events = []
			for event in all_results:
				export_events.append({
					'date': event['timestamp'],
					'hostname': event['hostname'],
					'keyword': event['keyword'],
					'event_type': event['event_type'],
					'file_name': event['file_name'],
					'file_sha256': event['file_sha256'],
					'file_path': event['file_path'],
					'arguments': event['arguments'],
					'parent_sha256': event['parent_sha256']
				})

			CSVExporter.export_events(
				export_events,
				args.csv,
				fields=['date', 'hostname', 'keyword', 'event_type', 'file_name',
						'file_sha256', 'file_path', 'arguments', 'parent_sha256']
			)
			print(f'[+] CSV export complete: {args.csv}')

		print("\n[+] Done")


if __name__ == "__main__":
	main()