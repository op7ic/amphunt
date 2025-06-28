#!/usr/bin/env python3
"""
Script Name: lateral_movement.py
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt

lateral_movement.py - Detect potential lateral movement activity

This script identifies potential lateral movement by monitoring specific ports
commonly used for remote access and administration (SMB, RDP, WinRM, RPC).

Usage:
	python lateral_movement.py -c/--config <config_file> [--csv output.csv]
"""

import sys
import argparse
from collections import defaultdict
from datetime import datetime
from amp_client import AMPClient, Config
from amp_client.utils import CSVExporter, LateralMovementDetector, OutputFormatter


# Lateral movement ports and their descriptions
LATERAL_MOVEMENT_PORTS = {
	139: 'SMB (NetBIOS)',
	445: 'SMB',
	3389: 'RDP',
	5985: 'WINRM - HTTP',
	5986: 'WINRM - HTTPS',
	135: 'WMIC/SC (RPC)'
}


def analyze_connection(event, hostname):
	"""Analyze a network connection for lateral movement indicators"""
	details = event.network_info
	if not details:
		return None

	direction_str = details.get('nfm', {}).get('direction', '')
	local_port = details.get('local_port')
	remote_port = details.get('remote_port')

	# Check for lateral movement based on direction and ports
	if 'Outgoing' in direction_str and remote_port in LATERAL_MOVEMENT_PORTS:
		return {
			'type': 'outbound',
			'service': LATERAL_MOVEMENT_PORTS[remote_port],
			'port': remote_port,
			'direction_string': direction_str
		}
	elif 'Incoming' in direction_str and local_port in LATERAL_MOVEMENT_PORTS:
		return {
			'type': 'inbound',
			'service': LATERAL_MOVEMENT_PORTS[local_port],
			'port': local_port,
			'direction_string': direction_str
		}

	return None


def main():
	parser = argparse.ArgumentParser(description='Detect lateral movement activity in AMP')
	parser.add_argument('-c', '--config', required=True, help='Configuration file path')
	parser.add_argument('--csv', help='Export results to CSV file')
	parser.add_argument('--limit', type=int, help='Limit number of computers to process')
	parser.add_argument('--summary', action='store_true', help='Show summary statistics')
	args = parser.parse_args()

	# Load configuration
	config = Config.from_file(args.config)

	# Create client
	with AMPClient(config) as client:
		# Get all computers
		print('[+] Fetching computers...')
		computers = list(client.computers.list())

		if args.limit:
			computers = computers[:args.limit]

		print(f'[+] Total computers found: {len(computers)}')

		# Track lateral movement events
		all_events = []
		lateral_movement_stats = defaultdict(lambda: {
			'outbound': defaultdict(int),
			'inbound': defaultdict(int)
		})

		# Process each computer
		for computer in computers:
			print(f'\n\t[+] Querying: {computer.hostname} - {computer.connector_guid}')

			try:
				# Get trajectory
				trajectory = client.computers.get_trajectory(computer.connector_guid)

				# Look for lateral movement indicators
				lm_events = 0
				for event in trajectory.events:
					if str(event.event_type) == 'NFM' and event.network_info:
						analysis = analyze_connection(event, computer.hostname)

						if analysis:
							details = event.network_info
							timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
							protocol = details.get('nfm', {}).get('protocol', 'unknown')
							local_ip = details.get('local_ip', 'unknown')
							local_port = details.get('local_port', 'unknown')
							remote_ip = details.get('remote_ip', 'unknown')
							remote_port = details.get('remote_port', 'unknown')

							# Track statistics
							lateral_movement_stats[computer.hostname][analysis['type']][analysis['service']] += 1

							# Display event
							if analysis['type'] == 'outbound':
								print(f'\t\t\t {timestamp} : outbound {analysis["service"]} : '
									  f'{computer.hostname} : {protocol} {local_ip}:{local_port} '
									  f'-> {remote_ip}:{remote_port}')
							else:
								print(f'\t\t\t {timestamp} : inbound {analysis["service"]} : '
									  f'{computer.hostname} : {protocol} {local_ip}:{local_port} '
									  f'<- {remote_ip}:{remote_port}')

							# Store for CSV export
							all_events.append({
								'timestamp': timestamp,
								'hostname': computer.hostname,
								'direction': analysis['type'],
								'service': analysis['service'],
								'protocol': protocol,
								'local_ip': local_ip,
								'local_port': local_port,
								'remote_ip': remote_ip,
								'remote_port': remote_port
							})
							lm_events += 1

				if lm_events == 0:
					print(f"\t\t [-] No lateral movement indicators found")

			except Exception as e:
				print(f"\t\t [!] Error processing {computer.hostname}: {e}")
				continue

		# Show summary if requested
		if args.summary and lateral_movement_stats:
			print("\n[+] Lateral Movement Summary:")

			# Sort by total events
			sorted_computers = sorted(
				lateral_movement_stats.items(),
				key=lambda x: sum(sum(port_counts.values()) 
								 for port_counts in x[1].values()),
				reverse=True
			)

			for hostname, stats in sorted_computers[:20]:
				total_events = sum(sum(port_counts.values()) 
								 for port_counts in stats.values())
				if total_events > 0:
					print(f"\n\t{hostname} ({total_events} total events):")

					# Outbound connections
					if stats['outbound']:
						print("\t  Outbound:")
						for service, count in sorted(stats['outbound'].items(), 
													key=lambda x: x[1], 
													reverse=True):
							print(f"\t    {service}: {count}")

					# Inbound connections
					if stats['inbound']:
						print("\t  Inbound:")
						for service, count in sorted(stats['inbound'].items(), 
													key=lambda x: x[1], 
													reverse=True):
							print(f"\t    {service}: {count}")

		# Export to CSV if requested
		if args.csv and all_events:
			print(f'\n[+] Exporting {len(all_events)} events to {args.csv}...')

			# Convert to format for CSVExporter
			export_events = []
			for event in all_events:
				export_events.append({
					'date': event['timestamp'],
					'hostname': event['hostname'],
					'event_type': f'Lateral Movement - {event["service"]}',
					'direction': event['direction'],
					'service': event['service'],
					'protocol': event['protocol'],
					'local_ip': event['local_ip'],
					'local_port': event['local_port'],
					'remote_ip': event['remote_ip'],
					'remote_port': event['remote_port']
				})

			CSVExporter.export_events(
				export_events,
				args.csv,
				fields=['date', 'hostname', 'event_type', 'direction', 'service',
						'protocol', 'local_ip', 'local_port', 'remote_ip', 'remote_port']
			)
			print(f'[+] CSV export complete: {args.csv}')

		print(f"\n[+] Total lateral movement events found: {len(all_events)}")
		print("[+] Done")


if __name__ == "__main__":
	main()