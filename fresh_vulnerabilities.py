#!/usr/bin/env python3
"""
Script Name: fresh_vulnerabilities.py
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt

fresh_vulnerabilities.py - Extract vulnerable application detections

This script identifies all vulnerable applications detected across your AMP
environment, including CVE details, CVSS scores, and affected systems.

Usage:
	python fresh_vulnerabilities.py -c/--config <config_file> [--csv output.csv]
"""

import sys
import argparse
from collections import defaultdict
from amp_client import AMPClient, Config
from amp_client.utils import CSVExporter


def calculate_average_cvss(vulnerabilities):
	"""Calculate average CVSS score from vulnerability list"""
	if not vulnerabilities:
		return 0

	scores = []
	for vuln in vulnerabilities:
		try:
			score = float(vuln.get('score', 0))
			if score > 0:
				scores.append(score)
		except (ValueError, TypeError):
			continue

	return round(sum(scores) / len(scores), 1) if scores else 0


def main():
	parser = argparse.ArgumentParser(description='Extract vulnerable application detections from AMP')
	parser.add_argument('-c', '--config', required=True, help='Configuration file path')
	parser.add_argument('--csv', help='Export results to CSV file')
	parser.add_argument('--limit', type=int, help='Limit number of computers to process')
	parser.add_argument('--summary', action='store_true', help='Show vulnerability summary')
	args = parser.parse_args()

	# Load configuration
	config = Config.from_file(args.config)

	# Print CSV header
	print('date,guid,hostname,type,severity,file_name,file_sha256,product_name,'
		  'oldest_CVE,oldest_version_impacted,oldest_cvss_score,average_cvss,'
		  'all_CVE,oldest_reference_url')

	# Create client
	with AMPClient(config) as client:
		# Get all computers
		print('[+] Fetching computers...', file=sys.stderr)
		computers = list(client.computers.list())

		if args.limit:
			computers = computers[:args.limit]

		print(f'[+] Total computers found: {len(computers)}', file=sys.stderr)

		# Collect all vulnerabilities
		all_vulnerabilities = []
		vulnerability_stats = defaultdict(lambda: {'count': 0, 'computers': set(), 'cves': set()})

		# Process each computer
		for computer in computers:
			try:
				# Get trajectory
				trajectory = client.computers.get_trajectory(computer.connector_guid)

				# Look for vulnerable application events
				for event in trajectory.events:
					if event.event_type == 'Vulnerable Application Detected':
						# Extract vulnerability details
						severity = event.severity or 'Unknown'
						file_info = event.file or {}
						file_name = file_info.get('file_name', 'Unknown')
						file_sha256 = file_info.get('identity', {}).get('sha256', 'Unknown')

						# Get vulnerability information
						vulnerabilities = event.__dict__.get('vulnerabilities', [])
						if vulnerabilities:
							# Get oldest (first) vulnerability
							oldest_vuln = vulnerabilities[0]
							product_name = oldest_vuln.get('name', 'Unknown')
							oldest_cve = oldest_vuln.get('cve', 'Unknown')
							oldest_version = oldest_vuln.get('version', 'Unknown')
							oldest_score = oldest_vuln.get('score', 0)
							oldest_url = oldest_vuln.get('url', '')

							# Collect all CVEs
							all_cves = [v.get('cve', '') for v in vulnerabilities if v.get('cve')]
							cve_list = '|'.join(all_cves)

							# Calculate average CVSS
							avg_cvss = calculate_average_cvss(vulnerabilities)

							# Track statistics
							vulnerability_stats[product_name]['count'] += 1
							vulnerability_stats[product_name]['computers'].add(computer.hostname)
							vulnerability_stats[product_name]['cves'].update(all_cves)

							# Print CSV row
							print(f"{event.date},{computer.connector_guid},{computer.hostname},"
								  f"Vulnerable Application,{severity},{file_name},{file_sha256},"
								  f"{product_name},{oldest_cve},{oldest_version},{oldest_score},"
								  f"{avg_cvss},{cve_list},{oldest_url}")

							# Store for export
							all_vulnerabilities.append({
								'date': event.date,
								'guid': computer.connector_guid,
								'hostname': computer.hostname,
								'type': 'Vulnerable Application',
								'severity': severity,
								'file_name': file_name,
								'file_sha256': file_sha256,
								'product_name': product_name,
								'oldest_CVE': oldest_cve,
								'oldest_version_impacted': oldest_version,
								'oldest_cvss_score': oldest_score,
								'average_cvss': avg_cvss,
								'all_CVE': cve_list,
								'oldest_reference_url': oldest_url
							})

			except Exception as e:
				print(f"Error processing {computer.hostname}: {e}", file=sys.stderr)
				continue

		# Show summary if requested
		if args.summary and vulnerability_stats:
			print("\n[+] Vulnerability Summary:", file=sys.stderr)
			sorted_vulns = sorted(vulnerability_stats.items(), 
								key=lambda x: x[1]['count'], 
								reverse=True)

			for product, stats in sorted_vulns[:20]:
				print(f"\n\t{product}:", file=sys.stderr)
				print(f"\t  Detections: {stats['count']}", file=sys.stderr)
				print(f"\t  Affected computers: {len(stats['computers'])}", file=sys.stderr)
				print(f"\t  Unique CVEs: {len(stats['cves'])}", file=sys.stderr)
				if len(stats['cves']) <= 5:
					print(f"\t  CVEs: {', '.join(sorted(stats['cves']))}", file=sys.stderr)

		# Export to CSV if requested
		if args.csv and all_vulnerabilities:
			print(f'\n[+] Exporting {len(all_vulnerabilities)} vulnerabilities to {args.csv}...', 
				  file=sys.stderr)

			CSVExporter.export_events(
				all_vulnerabilities,
				args.csv,
				fields=['date', 'guid', 'hostname', 'type', 'severity', 
						'file_name', 'file_sha256', 'product_name',
						'oldest_CVE', 'oldest_version_impacted', 
						'oldest_cvss_score', 'average_cvss', 'all_CVE',
						'oldest_reference_url']
			)
			print(f'[+] CSV export complete: {args.csv}', file=sys.stderr)

		print(f"\n[+] Total vulnerabilities found: {len(all_vulnerabilities)}", file=sys.stderr)
		print("[+] Done", file=sys.stderr)


if __name__ == "__main__":
	main()