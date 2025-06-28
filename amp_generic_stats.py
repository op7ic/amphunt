#!/usr/bin/env python3
"""
Script Name: amp_generic_stats.py
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt

amp_generic_stats.py - Generate statistics for AMP environment

This script generates comprehensive statistics about your AMP environment,
including event counts by type, threat detections, and system activity.

Usage:
	python amp_generic_stats.py -c <config_file> [--csv output.csv]
"""

import sys
import argparse
from collections import defaultdict
from datetime import datetime
from amp_client import AMPClient, Config
from amp_client.models import EventType
from amp_client.utils import CSVExporter


def main():
	parser = argparse.ArgumentParser(description='Generate AMP environment statistics')
	parser.add_argument('-c', '--config', required=True, help='Configuration file path')
	parser.add_argument('--csv', help='Export results to CSV file')
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
			# Print CSV header
			print('\ndate,guid,hostname,Vulnerable Application Detected,NFM,File Executed,'
				  'File Created,File Moved,Threat Quarantined,Threat Detected,'
				  'Quarantine Failure,Malicious Activity Detection,Execution Blocked,Executed malware')

		# Collect all stats for CSV export
		all_stats = []

		# Process each computer
		for computer in computers:
			try:
				# Get trajectory
				trajectory = client.computers.get_trajectory(computer.connector_guid)

				# Initialize counters
				stats = defaultdict(int)
				last_event_date = None

				# Count events by type
				for event in trajectory.events:
					event_type = event.event_type
					last_event_date = event.timestamp

					# Map event types to our categories
					if event_type == 'Vulnerable Application Detected':
						stats['vulnerable'] += 1
					elif event_type == 'NFM':
						stats['nfm'] += 1
					elif 'Executed' in event_type and 'Blocked' not in event_type:
						stats['executed'] += 1
					elif 'Created' in event_type:
						stats['created'] += 1
					elif 'Moved' in event_type:
						stats['moved'] += 1
					elif event_type == 'Threat Quarantined':
						stats['threat_quarantined'] += 1
					elif event_type == 'Threat Detected':
						stats['threat_detected'] += 1
					elif event_type == 'Quarantine Failure':
						stats['quarantine_fail'] += 1
					elif event_type == 'Malicious Activity Detection':
						stats['malicious_activity'] += 1
					elif event_type == 'Execution Blocked':
						stats['exec_blocked'] += 1
					elif event_type == 'Executed Malware':
						stats['exec_malware'] += 1

				# Use last event date or current time
				date_str = last_event_date.strftime("%Y-%m-%d %H:%M:%S") if last_event_date else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

				# Print stats (only in non-CSV mode)
				if not args.csv:
					print(f"{date_str},{computer.connector_guid},{computer.hostname},"
						  f"{stats['vulnerable']},{stats['nfm']},{stats['executed']},"
						  f"{stats['created']},{stats['moved']},{stats['threat_quarantined']},"
						  f"{stats['threat_detected']},{stats['quarantine_fail']},"
						  f"{stats['malicious_activity']},{stats['exec_blocked']},{stats['exec_malware']}")

				# Store for CSV export
				all_stats.append({
					'date': date_str,
					'guid': computer.connector_guid,
					'hostname': computer.hostname,
					'vulnerable': stats['vulnerable'],
					'nfm': stats['nfm'],
					'executed': stats['executed'],
					'created': stats['created'],
					'moved': stats['moved'],
					'threat_quarantined': stats['threat_quarantined'],
					'threat_detected': stats['threat_detected'],
					'quarantine_fail': stats['quarantine_fail'],
					'malicious_activity': stats['malicious_activity'],
					'exec_blocked': stats['exec_blocked'],
					'exec_malware': stats['exec_malware']
				})

			except Exception as e:
				print(f"Error processing {computer.hostname}: {e}", file=sys.stderr)
				continue

		# Generate summary statistics
		if not args.csv:
			print("\n[+] Summary Statistics:")

		# Total events by category
		total_stats = defaultdict(int)
		for stat in all_stats:
			for key, value in stat.items():
				if key not in ['date', 'guid', 'hostname']:
					total_stats[key] += value

		if not args.csv:
			print(f"\n\tTotal Vulnerable Applications: {total_stats['vulnerable']}")
			print(f"\tTotal Network Events (NFM): {total_stats['nfm']}")
			print(f"\tTotal Files Executed: {total_stats['executed']}")
			print(f"\tTotal Files Created: {total_stats['created']}")
			print(f"\tTotal Files Moved: {total_stats['moved']}")
			print(f"\tTotal Threats Quarantined: {total_stats['threat_quarantined']}")
			print(f"\tTotal Threats Detected: {total_stats['threat_detected']}")
			print(f"\tTotal Quarantine Failures: {total_stats['quarantine_fail']}")
			print(f"\tTotal Malicious Activity: {total_stats['malicious_activity']}")
			print(f"\tTotal Executions Blocked: {total_stats['exec_blocked']}")
			print(f"\tTotal Malware Executed: {total_stats['exec_malware']}")

		# Top computers by threat activity
		threat_computers = []
		for stat in all_stats:
			threat_score = (stat['threat_detected'] + stat['threat_quarantined'] + 
						   stat['malicious_activity'] + stat['exec_malware'])
			if threat_score > 0:
				threat_computers.append((stat['hostname'], threat_score))

		if threat_computers and not args.csv:
			print("\n\t[+] Top 10 Computers by Threat Activity:")
			for hostname, score in sorted(threat_computers, key=lambda x: x[1], reverse=True)[:10]:
				print(f"\t\t{hostname}: {score} threat events")

		# Export to CSV if requested
		if args.csv and all_stats:

			# Convert to format for CSVExporter
			export_events = []
			for stat in all_stats:
				export_events.append({
					'date': stat['date'],
					'connector_guid': stat['guid'],
					'hostname': stat['hostname'],
					'Vulnerable Application Detected': stat['vulnerable'],
					'NFM': stat['nfm'],
					'File Executed': stat['executed'],
					'File Created': stat['created'],
					'File Moved': stat['moved'],
					'Threat Quarantined': stat['threat_quarantined'],
					'Threat Detected': stat['threat_detected'],
					'Quarantine Failure': stat['quarantine_fail'],
					'Malicious Activity Detection': stat['malicious_activity'],
					'Execution Blocked': stat['exec_blocked'],
					'Executed malware': stat['exec_malware']
				})

			CSVExporter.export_events(
				export_events,
				args.csv,
				fields=['date', 'connector_guid', 'hostname', 
						'Vulnerable Application Detected', 'NFM', 'File Executed',
						'File Created', 'File Moved', 'Threat Quarantined',
						'Threat Detected', 'Quarantine Failure', 
						'Malicious Activity Detection', 'Execution Blocked',
						'Executed malware']
			)

		if not args.csv:
			print("\n[+] Done")


if __name__ == "__main__":
	main()