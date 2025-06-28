#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Output formatting utilities
"""

import json
import csv
from typing import List, Dict, Any, Optional, IO
from datetime import datetime
from urllib.parse import urlparse
import re


class OutputFormatter:
	"""Base formatter class"""

	@staticmethod
	def sanitize_url(url: str) -> str:
		"""Sanitize URL for safe display - only sanitize last dot"""
		if '.' in url:
			# Replace only the last dot with [.]
			last_dot_index = url.rfind('.')
			url = url[:last_dot_index] + '[.]' + url[last_dot_index+1:]
		return url.replace('http', 'hxxp')

	@staticmethod
	def sanitize_ip(ip: str) -> str:
		"""Sanitize IP for safe display - only sanitize last dot"""
		if '.' in ip:
			# Replace only the last dot with [.]
			last_dot_index = ip.rfind('.')
			ip = ip[:last_dot_index] + '[.]' + ip[last_dot_index+1:]
		return ip

	@staticmethod
	def format_timestamp(timestamp: str, format: str = "%Y-%m-%d %H:%M:%S") -> str:
		"""Format timestamp string"""
		dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
		return dt.strftime(format)

	@staticmethod
	def extract_domain(url: str) -> str:
		"""Extract domain from URL"""
		return urlparse(url).netloc


class NetworkEventFormatter(OutputFormatter):
	"""Format network events for display"""

	@staticmethod
	def format_connection(event: Dict[str, Any], sanitize: bool = True) -> str:
		"""Format network connection event"""
		network_info = event.get('network_info', {})

		local_ip = network_info.get('local_ip', 'unknown')
		local_port = network_info.get('local_port', 'unknown')
		remote_ip = network_info.get('remote_ip', 'unknown')
		remote_port = network_info.get('remote_port', 'unknown')
		protocol = network_info.get('nfm', {}).get('protocol', 'unknown')

		if sanitize:
			local_ip = OutputFormatter.sanitize_ip(local_ip)
			remote_ip = OutputFormatter.sanitize_ip(remote_ip)

		direction = network_info.get('nfm', {}).get('direction', '')
		if 'Outgoing' in direction:
			arrow = '->'
		elif 'Incoming' in direction:
			arrow = '<-'
		else:
			arrow = '--'

		return f"{protocol} {local_ip}:{local_port} {arrow} {remote_ip}:{remote_port}"

	@staticmethod
	def format_url_event(event: Dict[str, Any], sanitize: bool = True) -> str:
		"""Format URL-based network event"""
		network_info = event.get('network_info', {})
		url = network_info.get('dirty_url', '')

		if not url:
			return NetworkEventFormatter.format_connection(event, sanitize)

		domain = OutputFormatter.extract_domain(url)
		if sanitize:
			url = OutputFormatter.sanitize_url(url)
			domain = OutputFormatter.sanitize_url(domain)

		connection = NetworkEventFormatter.format_connection(event, sanitize)
		return f"{connection} | URL: {url} | Domain: {domain}"


class FileEventFormatter(OutputFormatter):
	"""Format file events for display"""

	@staticmethod
	def format_file_info(file_info: Dict[str, Any]) -> Dict[str, Any]:
		"""Format file information"""
		return {
			'name': file_info.get('file_name', 'unknown'),
			'path': file_info.get('file_path', 'unknown'),
			'sha256': file_info.get('identity', {}).get('sha256', 'unknown'),
			'type': file_info.get('file_type', 'unknown'),
			'disposition': file_info.get('disposition', 'unknown')
		}

	@staticmethod
	def format_process_tree(event: Dict[str, Any]) -> str:
		"""Format process execution tree"""
		file_info = event.get('file', {})
		parent_info = file_info.get('parent', {})

		result = []

		# Parent process
		if parent_info:
			parent_name = parent_info.get('file_name', 'unknown')
			parent_sha = parent_info.get('identity', {}).get('sha256', 'unknown')[:8]
			result.append(f"Parent: {parent_name} ({parent_sha}...)")

		# Current process
		current_name = file_info.get('file_name', 'unknown')
		current_sha = file_info.get('identity', {}).get('sha256', 'unknown')[:8]
		result.append(f"  └─> {current_name} ({current_sha}...)")

		# Command line if available
		if 'command_line' in event:
			args = event['command_line'].get('arguments', [])
			if isinstance(args, list):
				args = ' '.join(args)
			if args:
				result.append(f"      Args: {args}")

		return '\n'.join(result)


class CSVExporter:
	"""Export data to CSV format"""

	@staticmethod
	def export_events(events: List[Dict[str, Any]], output_file: str,
					 fields: Optional[List[str]] = None):
		"""Export events to CSV"""
		if not events:
			return

		# Default fields if not specified
		if not fields:
			fields = [
				'date', 'event_type', 'hostname', 'connector_guid',
				'file_name', 'file_path', 'file_sha256', 'disposition',
				'local_ip', 'local_port', 'remote_ip', 'remote_port',
				'url', 'detection_name', 'severity'
			]

		with open(output_file, 'w', newline='', encoding='utf-8') as f:
			writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
			writer.writeheader()

			for event in events:
				row = {
					'date': event.get('date', ''),
					'event_type': event.get('event_type', ''),
					'hostname': event.get('computer', {}).get('hostname', ''),
					'connector_guid': event.get('connector_guid', ''),
					'severity': event.get('severity', '')
				}

				# File information
				if 'file' in event:
					file_info = event['file']
					row.update({
						'file_name': file_info.get('file_name', ''),
						'file_path': file_info.get('file_path', ''),
						'file_sha256': file_info.get('identity', {}).get('sha256', ''),
						'disposition': file_info.get('disposition', '')
					})

				# Network information
				if 'network_info' in event:
					net_info = event['network_info']
					row.update({
						'local_ip': net_info.get('local_ip', ''),
						'local_port': net_info.get('local_port', ''),
						'remote_ip': net_info.get('remote_ip', ''),
						'remote_port': net_info.get('remote_port', ''),
						'url': net_info.get('dirty_url', '')
					})

				# Detection information
				if 'detection' in event:
					row['detection_name'] = event['detection'].get('name', '')

				writer.writerow(row)

	@staticmethod
	def export_trajectory(trajectory: Dict[str, Any], output_file: str):
		"""Export trajectory data to CSV"""
		events = trajectory.get('events', [])
		CSVExporter.export_events(events, output_file)


class JSONExporter:
	"""Export data to JSON format"""

	@staticmethod
	def export_events(events: List[Dict[str, Any]], output_file: str,
					 pretty: bool = True):
		"""Export events to JSON"""
		with open(output_file, 'w', encoding='utf-8') as f:
			if pretty:
				json.dump(events, f, indent=2, ensure_ascii=False)
			else:
				json.dump(events, f, ensure_ascii=False)

	@staticmethod
	def export_timeline(events: List[Dict[str, Any]], output_file: str):
		"""Export events as timeline JSON"""
		timeline = []

		for event in sorted(events, key=lambda x: x.get('date', '')):
			timeline_entry = {
				'timestamp': event.get('date'),
				'type': event.get('event_type'),
				'computer': event.get('computer', {}).get('hostname', 'unknown'),
				'description': JSONExporter._build_description(event)
			}
			timeline.append(timeline_entry)

		with open(output_file, 'w', encoding='utf-8') as f:
			json.dump(timeline, f, indent=2, ensure_ascii=False)

	@staticmethod
	def _build_description(event: Dict[str, Any]) -> str:
		"""Build human-readable description for event"""
		event_type = event.get('event_type', 'Unknown')

		if 'file' in event:
			file_name = event['file'].get('file_name', 'unknown file')
			return f"{event_type}: {file_name}"
		elif 'network_info' in event:
			return NetworkEventFormatter.format_connection(event, sanitize=False)
		else:
			return event_type