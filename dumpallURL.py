#!/usr/bin/env python3
"""
Script Name: dumpallURL.py
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt

dumpallURL.py - Extract all URL requests from all computers

This script retrieves all URL-based network events from all computers
in your AMP environment, useful for identifying suspicious domains,
C2 communications, and data exfiltration attempts.

Usage:
	python dumpallURL.py -c/--config <config_file> [--csv output.csv]
"""

import sys
import argparse
from collections import defaultdict
from amp_client import AMPClient, Config
from amp_client.utils import OutputFormatter, CSVExporter


def main():
	parser = argparse.ArgumentParser(description='Extract all URL requests from AMP')
	parser.add_argument('-c', '--config', required=True, help='Configuration file path')
	parser.add_argument('--csv', help='Export results to CSV file')
	parser.add_argument('--no-sanitize', action='store_true', help='Do not sanitize URLs and IPs')
	parser.add_argument('--limit', type=int, help='Limit number of computers to process')
	parser.add_argument('--summary', action='store_true', help='Show domain summary at the end')
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

		# Collect all URL events
		all_url_events = []
		domain_stats = defaultdict(lambda: {'count': 0, 'computers': set()})

		# Process each computer
		for computer in computers:
			print(f'\n\t[+] Querying: {computer.hostname} - {computer.connector_guid}')

			try:
				# Get trajectory
				trajectory = client.computers.get_trajectory(computer.connector_guid)

				# Process events looking for URLs
				url_count = 0
				for event in trajectory.events:
					# Check for URL events
					if (event.event_type == 'NFM' and event.network_info and 
						'dirty_url' in event.network_info):

						details = event.network_info
						url = details['dirty_url']
						domain = OutputFormatter.extract_domain(url)
						direction = details.get('nfm', {}).get('direction', '')
						timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")

						# Track domain statistics
						domain_stats[domain]['count'] += 1
						domain_stats[domain]['computers'].add(computer.hostname)

						# Sanitize if requested
						display_url = OutputFormatter.sanitize_url(url) if not args.no_sanitize else url
						display_domain = OutputFormatter.sanitize_url(domain) if not args.no_sanitize else domain

						# Display based on direction
						if 'Outgoing' in direction:
							print(f"\t\t [+] Outbound URL request at hostname: {computer.hostname}")
							print(f'\t\t\t {timestamp} Host: {computer.hostname} URL: {display_url} DOMAIN: {display_domain}')
						elif 'Incoming' in direction:
							print(f"\t\t [+] Inbound URL request at hostname: {computer.hostname}")
							print(f'\t\t\t {timestamp} Host: {computer.hostname} URL: {display_url} DOMAIN: {display_domain}')

						# Store for CSV export
						all_url_events.append({
							'timestamp': timestamp,
							'hostname': computer.hostname,
							'connector_guid': computer.connector_guid,
							'direction': 'outbound' if 'Outgoing' in direction else 'inbound',
							'url': url,
							'domain': domain,
							'local_ip': details.get('local_ip', ''),
							'local_port': details.get('local_port', ''),
							'remote_ip': details.get('remote_ip', ''),
							'remote_port': details.get('remote_port', ''),
							'protocol': details.get('nfm', {}).get('protocol', '')
						})
						url_count += 1

				if url_count == 0:
					print(f"\t\t [-] No URL events found")
				else:
					print(f"\t\t [+] Found {url_count} URL events")

			except Exception as e:
				print(f"\t\t [!] Error processing {computer.hostname}: {e}")
				continue

		# Show domain summary if requested
		if args.summary and domain_stats:
			print("\n[+] Domain Summary (Top 20 by request count):")
			sorted_domains = sorted(domain_stats.items(), 
								   key=lambda x: x[1]['count'], 
								   reverse=True)[:20]

			for domain, stats in sorted_domains:
				display_domain = OutputFormatter.sanitize_url(domain) if not args.no_sanitize else domain
				print(f"\n\t{display_domain}")
				print(f"\t  Requests: {stats['count']}")
				print(f"\t  Seen on {len(stats['computers'])} computer(s)")
				if len(stats['computers']) <= 5:
					print(f"\t  Computers: {', '.join(sorted(stats['computers']))}")

		# Export to CSV if requested
		if args.csv and all_url_events:
			print(f'\n[+] Exporting {len(all_url_events)} URL events to {args.csv}...')

			# Convert to format for CSVExporter
			export_events = []
			for event in all_url_events:
				export_events.append({
					'date': event['timestamp'],
					'hostname': event['hostname'],
					'connector_guid': event['connector_guid'],
					'event_type': 'URL Request',
					'direction': event['direction'],
					'url': event['url'],
					'domain': event['domain'],
					'local_ip': event['local_ip'],
					'local_port': event['local_port'],
					'remote_ip': event['remote_ip'],
					'remote_port': event['remote_port']
				})

			CSVExporter.export_events(
				export_events,
				args.csv,
				fields=['date', 'hostname', 'direction', 'domain', 'url', 
						'local_ip', 'local_port', 'remote_ip', 'remote_port']
			)
			print(f'[+] CSV export complete: {args.csv}')

		print(f"\n[+] Total URL events found: {len(all_url_events)}")
		print("[+] Done")


if __name__ == "__main__":
	main()