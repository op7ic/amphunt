#!/usr/bin/env python3
"""
Script Name: hash2connection.py
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt

hash2connection.py - Find network connections related to specific file hashes

This script searches for network connections associated with files matching
the provided SHA256 hashes, helping identify C2 communications and data exfiltration.

Usage:
	python hash2connection.py -c/--config <config_file> <hashfile.txt> [--csv output.csv]
"""

import sys
import argparse
from collections import defaultdict
from amp_client import AMPClient, Config
from amp_client.utils import NetworkEventFormatter, CSVExporter, OutputFormatter


def process_hash(client, sha256, csv_export=False):
	"""Process a single hash and find associated network connections"""
	print(f"\n[+] Hunting for hash: {sha256}")

	# Track remote IPs and computers
	remote_ips = defaultdict(lambda: {'ports': set(), 'computers': set()})
	computers_found = {}
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

			# Process events
			network_events = 0
			for event in trajectory.events:
				# Handle network events
				if event.event_type == 'NFM' and event.network_info:
					details = event.network_info
					remote_ip = details.get('remote_ip')
					remote_port = details.get('remote_port')

					# Track remote IPs
					if remote_ip and remote_port:
						remote_ips[remote_ip]['ports'].add(remote_port)
						remote_ips[remote_ip]['computers'].add(hostname)

					# Format and display
					direction = details.get('nfm', {}).get('direction', '')
					timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")

					if 'Outgoing' in direction:
						print(f"\t\t [+] Outbound network event at hostname: {hostname}")
						connection = NetworkEventFormatter.format_connection(
							{'network_info': details}, sanitize=False
						)
						print(f'\t\t\t {timestamp} : {hostname} : {connection}')

						# Handle URL events
						if 'dirty_url' in details:
							url = details['dirty_url']
							print(f'\t\t\t {timestamp} : Host: {hostname} URL: {url}')

						all_events.append({
							'hash': sha256,
							'timestamp': timestamp,
							'hostname': hostname,
							'direction': 'outbound',
							'protocol': details.get('nfm', {}).get('protocol', ''),
							'local_ip': details.get('local_ip', ''),
							'local_port': details.get('local_port', ''),
							'remote_ip': remote_ip or '',
							'remote_port': remote_port or '',
							'url': details.get('dirty_url', '')
						})
						network_events += 1

					elif 'Incoming' in direction:
						print(f"\t\t [+] Inbound network event at hostname: {hostname}")
						connection = NetworkEventFormatter.format_connection(
							{'network_info': details}, sanitize=False
						)
						print(f'\t\t\t {timestamp} : {hostname} : {connection}')

						all_events.append({
							'hash': sha256,
							'timestamp': timestamp,
							'hostname': hostname,
							'direction': 'inbound',
							'protocol': details.get('nfm', {}).get('protocol', ''),
							'local_ip': details.get('local_ip', ''),
							'local_port': details.get('local_port', ''),
							'remote_ip': remote_ip or '',
							'remote_port': remote_port or '',
							'url': ''
						})
						network_events += 1

				# Handle DFC threats
				elif event.event_type == 'DFC Threat Detected' and event.network_info:
					details = event.network_info
					remote_ip = details.get('remote_ip')
					remote_port = details.get('remote_port')
					timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")

					# Track remote IPs
					if remote_ip and remote_port:
						remote_ips[remote_ip]['ports'].add(remote_port)
						remote_ips[remote_ip]['computers'].add(hostname)

					print(f"\t\t [+] Device flow correlation network event at hostname: {hostname}")
					print(f'\t\t {timestamp} : {hostname} : DFC: '
						  f'{details.get("local_ip")}:{details.get("local_port")} - '
						  f'{remote_ip}:{remote_port}')

					all_events.append({
						'hash': sha256,
						'timestamp': timestamp,
						'hostname': hostname,
						'direction': 'DFC',
						'protocol': '',
						'local_ip': details.get('local_ip', ''),
						'local_port': details.get('local_port', ''),
						'remote_ip': remote_ip or '',
						'remote_port': remote_port or '',
						'url': ''
					})
					network_events += 1

			if network_events == 0:
				print(f"\t\t [-] No network events found for this hash")

		except Exception as e:
			print(f"\t\t [!] Error processing {hostname}: {e}")
			continue

	# Summary of remote IPs
	if remote_ips:
		print(f"\n\t[+] Summary of remote IPs contacted by {sha256}:")
		for ip, info in sorted(remote_ips.items()):
			ports = sorted(info['ports'])
			computers = sorted(info['computers'])
			print(f"\t\t{ip}")
			print(f"\t\t  Ports: {', '.join(map(str, ports))}")
			print(f"\t\t  Seen on: {', '.join(computers)}")

	return all_events


def main():
	parser = argparse.ArgumentParser(description='Find network connections for file hashes')
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
			events = process_hash(client, sha256, csv_export=bool(args.csv))
			all_results.extend(events)

		# Export to CSV if requested
		if args.csv and all_results:
			print(f'\n[+] Exporting {len(all_results)} events to {args.csv}...')

			# Convert to format for CSVExporter
			export_events = []
			for event in all_results:
				export_events.append({
					'date': event['timestamp'],
					'file_sha256': event['hash'],
					'hostname': event['hostname'],
					'event_type': f"Network Connection ({event['direction']})",
					'local_ip': event['local_ip'],
					'local_port': event['local_port'],
					'remote_ip': event['remote_ip'],
					'remote_port': event['remote_port'],
					'url': event['url']
				})

			CSVExporter.export_events(
				export_events,
				args.csv,
				fields=['date', 'file_sha256', 'hostname', 'event_type', 
						'local_ip', 'local_port', 'remote_ip', 'remote_port', 'url']
			)
			print(f'[+] CSV export complete: {args.csv}')

		print("\n[+] Done")


if __name__ == "__main__":
	main()