#!/usr/bin/env python3
"""
Script Name: allconnections.py
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt

allconnections.py - List all network connections across all computers

This script retrieves all network connection events (NFM, DFC) from all computers
in your AMP environment and displays them in a human-readable format.

Usage:
	python allconnections.py -c <config_file> [--csv output.csv]
"""

import sys
import argparse
from datetime import datetime
from amp_client import AMPClient, Config
from amp_client.utils import NetworkEventFormatter, CSVExporter, OutputFormatter


def format_network_event(event, hostname, sanitize=True):
	"""Format a network event for display"""
	details = event.network_info
	if not details:
		return None

	timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")

	# Get connection details
	local_ip = details.get('local_ip', 'unknown')
	local_port = details.get('local_port', 'unknown')
	remote_ip = details.get('remote_ip', 'unknown')
	remote_port = details.get('remote_port', 'unknown')
	protocol = details.get('nfm', {}).get('protocol', 'unknown')

	# Determine direction
	direction_str = details.get('nfm', {}).get('direction', '')
	if 'Outgoing' in direction_str:
		direction = 'outbound'
		arrow = '->'
	elif 'Incoming' in direction_str:
		direction = 'inbound'
		arrow = '<-'
	else:
		direction = 'unknown'
		arrow = '--'

	# Sanitize IPs if requested
	if sanitize:
		local_ip = OutputFormatter.sanitize_ip(local_ip)
		remote_ip = OutputFormatter.sanitize_ip(remote_ip)

	# Build connection string
	connection = f"{protocol} {local_ip}:{local_port} {arrow} {remote_ip}:{remote_port}"

	# Handle URL events
	url_info = ""
	if 'dirty_url' in details:
		url = details['dirty_url']
		domain = OutputFormatter.extract_domain(url)
		if sanitize:
			url = OutputFormatter.sanitize_url(url)
			domain = OutputFormatter.sanitize_url(domain)
		url_info = f" | DOMAIN: {domain} | URL: {url}"

	return {
		'timestamp': timestamp,
		'direction': direction,
		'hostname': hostname,
		'connection': connection,
		'url_info': url_info,
		'event_type': event.event_type,
		'local_ip': local_ip,
		'local_port': local_port,
		'remote_ip': remote_ip,
		'remote_port': remote_port,
		'protocol': protocol,
		'url': details.get('dirty_url', ''),
		'domain': OutputFormatter.extract_domain(details.get('dirty_url', '')) if 'dirty_url' in details else ''
	}


def main():
	parser = argparse.ArgumentParser(description='List all network connections from AMP')
	parser.add_argument('-c', '--config', required=True, help='Configuration file path')
	parser.add_argument('--csv', help='Export results to CSV file')
	parser.add_argument('--no-sanitize', action='store_true', help='Do not sanitize IPs and URLs')
	parser.add_argument('--limit', type=int, help='Limit number of computers to process')
	args = parser.parse_args()

	# Load configuration
	config = Config.from_file(args.config)

	# Create client
	with AMPClient(config) as client:
		# Get all computers
		if not args.csv:
			print('[+] Fetching computers...')
		computers = list(client.computers.list())

		if args.limit:
			computers = computers[:args.limit]

		if not args.csv:
			print(f'[+] Total computers found: {len(computers)}')

		# Collect all events for CSV export
		all_events = []

		# Process each computer
		for computer in computers:
			if not args.csv:
				print(f'\n\t[+] Querying: {computer.hostname} - {computer.connector_guid}')

			try:
				# Get trajectory
				trajectory = client.computers.get_trajectory(computer.connector_guid)

				# Process events
				network_event_count = 0
				for event in trajectory.events:
					# Handle Network File Move events
					if event.event_type == 'NFM' and event.network_info:
						formatted = format_network_event(event, computer.hostname, 
													   sanitize=not args.no_sanitize)
						if formatted:
							direction = formatted['direction']

							if not args.csv:
								if direction == 'outbound':
									print(f"\t\t [+] Outbound network event at hostname : {computer.hostname}")
								elif direction == 'inbound':
									print(f"\t\t [+] Inbound network event at hostname : {computer.hostname}")

								output = f"\t\t\t {formatted['timestamp']} : {direction} : {computer.hostname} : {formatted['connection']}"
								if formatted['url_info']:
									output += f"\n\t\t\t {formatted['timestamp']} : {computer.hostname} : {formatted['url_info']}"
								print(output)

							all_events.append(formatted)
							network_event_count += 1

					# Handle DFC Threat events
					elif event.event_type == 'DFC Threat Detected' and event.network_info:
						details = event.network_info
						timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")

						if not args.csv:
							print(f"\t\t [+] Device flow correlation network event at hostname : {computer.hostname}")
							print(f"\t\t\t {timestamp} : {computer.hostname} : DFC: "
								  f"{details.get('local_ip')}:{details.get('local_port')} - "
								  f"{details.get('remote_ip')}:{details.get('remote_port')}")

						# Add to events list
						all_events.append({
							'timestamp': timestamp,
							'direction': 'DFC Threat Detected',
							'hostname': computer.hostname,
							'connection': f"DFC: {details.get('local_ip')}:{details.get('local_port')} - "
										 f"{details.get('remote_ip')}:{details.get('remote_port')}",
							'url_info': '',
							'event_type': 'DFC Threat Detected',
							'local_ip': details.get('local_ip', ''),
							'local_port': details.get('local_port', ''),
							'remote_ip': details.get('remote_ip', ''),
							'remote_port': details.get('remote_port', ''),
							'protocol': '',
							'url': '',
							'domain': ''
						})
						network_event_count += 1

				if network_event_count == 0 and not args.csv:
					print(f"\t\t [-] No network events found")

			except Exception as e:
				if not args.csv:
					print(f"\t\t [!] Error processing {computer.hostname}: {e}")
				continue

		# Export to CSV if requested
		if args.csv and all_events:

			# Convert to format expected by CSVExporter
			export_events = []
			for event in all_events:
				export_events.append({
					'date': event['timestamp'],
					'connector_guid': event.get('guid', ''),
					'hostname': event['hostname'],
					'event_type': event['event_type'],
					'local_ip': event['local_ip'],
					'local_port': event['local_port'],
					'remote_ip': event['remote_ip'],
					'remote_port': event['remote_port'],
					'direction': event['direction'],
					'url': event['url'],
					'domain': event['domain']
				})

			CSVExporter.export_events(
				export_events, 
				args.csv,
				fields=['date', 'hostname', 'event_type', 'direction', 'local_ip', 
						'local_port', 'remote_ip', 'remote_port', 'domain', 'url']
			)

		if not args.csv:
			print("\n[+] Done")


if __name__ == "__main__":
	main()