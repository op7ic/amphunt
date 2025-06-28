#!/usr/bin/env python3
"""
Script Name: timeliner.py
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt

timeliner.py - Generate timeline of events for all computers

This script creates a comprehensive timeline of all events (file, network, threat)
for each computer in your AMP environment, saving them to individual files.

Usage:
	python timeliner.py -c/--config <config_file> -o <output_directory>
"""

import os
import sys
import argparse
from pathlib import Path
from amp_client import AMPClient, Config
from amp_client.utils import FileEventFormatter, NetworkEventFormatter, OutputFormatter


def validate_file(f):
	"""Validate that file exists"""
	if not os.path.exists(f):
		raise argparse.ArgumentTypeError(f"Path {f} does not exist")
	return f


def validate_dict_element(dictionary, field):
	"""Check if dictionary contains field"""
	try:
		_ = dictionary[field]
		return True
	except (KeyError, TypeError):
		return False


def format_arguments(arguments):
	"""Format command line arguments for display"""
	if isinstance(arguments, list):
		return ' '.join(arguments)
	return arguments or ''


def process_computer(client, computer, output_dir):
	"""Process a single computer and generate timeline"""
	print(f'\n\t\t[+] Querying: {computer.hostname} - {computer.connector_guid}')

	# Define output filename
	filename = os.path.join(output_dir, f"{computer.hostname}_{computer.connector_guid}.txt")

	try:
		# Get trajectory (max 500 events)
		trajectory = client.computers.get_trajectory(computer.connector_guid)

		# Open output file
		with open(filename, 'w', encoding='utf-8') as f:
			# Process each event
			event_count = 0
			for event in trajectory.events:
				timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
				event_type = event.event_type

				# Handle Threat Detected events
				if event_type == "Threat Detected":
					if hasattr(event, 'command_line') and event.command_line and 'arguments' in event.command_line:
						file_info = event.file or {}
						if validate_dict_element(file_info, 'parent'):
							arguments = format_arguments(event.command_line['arguments'])
							file_sha256 = file_info.get('identity', {}).get('sha256', 'unknown')
							parent_sha256 = file_info.get('parent', {}).get('identity', {}).get('sha256', 'unknown')
							file_name = file_info.get('file_name', 'unknown')
							disposition = file_info.get('disposition', 'unknown')

							f.write(f'{timestamp} : {computer.hostname} : {event_type} Parent SHA256 : {parent_sha256} '
								   f'File SHA256: {file_sha256} Process name: {file_name} Arguments: {arguments} '
								   f'Disposition: {disposition}\n')
						else:
							arguments = format_arguments(event.command_line['arguments'])
							file_sha256 = file_info.get('identity', {}).get('sha256', 'unknown')
							file_name = file_info.get('file_name', 'unknown')
							disposition = file_info.get('disposition', 'unknown')

							f.write(f'{timestamp} : {computer.hostname} : {event_type} File SHA256: {file_sha256} '
								   f'Process name: {file_name} Arguments: {arguments} Disposition: {disposition}\n')

					elif event.file and event.file.get('file_name'):
						file_info = event.file
						if validate_dict_element(file_info, 'parent'):
							f.write(f"{timestamp} : {computer.hostname} : {event_type} "
								   f"Parent SHA256: {file_info['parent']['identity']['sha256']} "
								   f"File Path: {file_info.get('file_path', 'unknown')} "
								   f"File SHA256: {file_info['identity']['sha256']} "
								   f"Disposition: {file_info.get('disposition', 'unknown')}\n")
						else:
							f.write(f"{timestamp} : {computer.hostname} : {event_type} "
								   f"File Path: {file_info.get('file_path', 'unknown')} "
								   f"File SHA256: {file_info['identity']['sha256']} "
								   f"Disposition: {file_info.get('disposition', 'unknown')}\n")

				# Handle file execution/creation/movement events
				elif event_type in ['Moved by', 'Malicious Activity Detection', 'Created by', 'Executed by']:
					if hasattr(event, 'command_line') and event.command_line and 'arguments' in event.command_line:
						file_info = event.file or {}
						if validate_dict_element(file_info, 'parent'):
							arguments = format_arguments(event.command_line['arguments'])
							file_sha256 = file_info.get('identity', {}).get('sha256', 'unknown')
							parent_sha256 = file_info.get('parent', {}).get('identity', {}).get('sha256', 'unknown')
							file_name = file_info.get('file_name', 'unknown')
							file_type = file_info.get('file_type', 'unknown')
							disposition = file_info.get('disposition', 'unknown')

							f.write(f'{timestamp} : {computer.hostname} : {event_type} Parent SHA256 : {parent_sha256} '
								   f'File SHA256: {file_sha256} Process name: {file_name} Arguments: {arguments} '
								   f'File Type: {file_type} Disposition: {disposition}\n')
						else:
							arguments = format_arguments(event.command_line['arguments'])
							file_sha256 = file_info.get('identity', {}).get('sha256', 'unknown')
							file_name = file_info.get('file_name', 'unknown')
							file_type = file_info.get('file_type', 'unknown')
							disposition = file_info.get('disposition', 'unknown')

							f.write(f'{timestamp} : {computer.hostname} : {event_type} File SHA256: {file_sha256} '
								   f'Process name: {file_name} Arguments: {arguments} File Type: {file_type} '
								   f'Disposition: {disposition}\n')

					elif event.file and event.file.get('file_name'):
						file_info = event.file
						if validate_dict_element(file_info, 'parent'):
							f.write(f"{timestamp} : {computer.hostname} : {event_type} "
								   f"Parent SHA256: {file_info['parent']['identity']['sha256']} "
								   f"File Path: {file_info.get('file_path', 'unknown')} "
								   f"File SHA256: {file_info['identity']['sha256']} "
								   f"File Type: {file_info.get('file_type', 'unknown')} "
								   f"Disposition: {file_info.get('disposition', 'unknown')}\n")
						else:
							f.write(f"{timestamp} : {computer.hostname} : {event_type} "
								   f"File Path: {file_info.get('file_path', 'unknown')} "
								   f"File SHA256: {file_info['identity']['sha256']} "
								   f"File Type: {file_info.get('file_type', 'unknown')} "
								   f"Disposition: {file_info.get('disposition', 'unknown')}\n")

				# Handle network events
				elif event_type == 'NFM' and event.network_info:
					details = event.network_info
					protocol = details.get('nfm', {}).get('protocol', 'unknown')
					local_ip = details.get('local_ip', 'unknown')
					local_port = details.get('local_port', 'unknown')
					remote_ip = details.get('remote_ip', 'unknown')
					remote_port = details.get('remote_port', 'unknown')
					direction = details.get('nfm', {}).get('direction', '')

					if 'Outgoing' in direction:
						f.write(f'{timestamp} : {computer.hostname} : outbound : '
							   f'{protocol} {local_ip}:{local_port} -> {remote_ip}:{remote_port}\n')
					elif 'Incoming' in direction:
						f.write(f'{timestamp} : {computer.hostname} : inbound : '
							   f'{protocol} {local_ip}:{local_port} <- {remote_ip}:{remote_port}\n')

					# Handle URL events
					if 'dirty_url' in details:
						url = details['dirty_url']
						domain = OutputFormatter.extract_domain(url)
						f.write(f'{timestamp} : {computer.hostname} : outbound : '
							   f'{protocol} {local_ip}:{local_port} -> {remote_ip}:{remote_port} '
							   f'URL: {OutputFormatter.sanitize_url(url)} '
							   f'DOMAIN: {OutputFormatter.sanitize_url(domain)}\n')

				# Handle DFC Threat events
				elif event_type == 'DFC Threat Detected' and event.network_info:
					details = event.network_info
					local_ip = details.get('local_ip', 'unknown')
					local_port = details.get('local_port', 'unknown')
					remote_ip = details.get('remote_ip', 'unknown')
					remote_port = details.get('remote_port', 'unknown')

					f.write(f'{timestamp} : {computer.hostname} DFC: '
						   f'{local_ip}:{local_port} - {remote_ip}:{remote_port}\n')

				# Handle Quarantine Failure events
				elif event_type == 'Quarantine Failure':
					severity = event.severity or 'unknown'
					file_info = event.file or {}
					disposition = file_info.get('disposition', 'unknown')
					file_sha256 = file_info.get('identity', {}).get('sha256', 'unknown')

					f.write(f'{timestamp} : {computer.hostname} : Event: {event_type} '
						   f'Severity: {severity} Disposition: {disposition} '
						   f'File SHA256: {file_sha256}\n')

				# Skip certain event types
				elif event_type in ['Vulnerable Application Detected', 'Policy Update']:
					pass

				# Log any other unhandled events
				else:
					f.write(f'{timestamp} : {computer.hostname} : {event_type}\n')

				event_count += 1

		print(f"\t\t\t[+] Wrote {event_count} events to {filename}")

	except Exception as e:
		print(f"\t\t\t[!] Error processing {computer.hostname}: {e}")


def main():
	# Parse arguments
	parser = argparse.ArgumentParser(description='Generate timeline for all computers')
	parser.add_argument('-c', '--config', required=True, help='Configuration file path')
	parser.add_argument('-o', '--output', required=True, dest='output_folder', help='Path to output folder')
	args = parser.parse_args()

	# Create output directory if it doesn't exist
	output_path = Path(args.output_folder)
	output_path.mkdir(parents=True, exist_ok=True)

	# Load configuration
	config = Config.from_file(args.config)

	# Create client
	with AMPClient(config) as client:
		# Get all computers
		print('[+] Fetching computers...')
		computers = list(client.computers.list())
		print(f'\t[+] Computers found: {len(computers)}')

		# Process each computer
		for computer in computers:
			process_computer(client, computer, args.output_folder)

		print("\n[+] Done")


if __name__ == "__main__":
	main()