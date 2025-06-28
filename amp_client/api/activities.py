#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Activity search API operations
"""

from typing import Optional, Dict, Any, List, Generator
from datetime import datetime, timedelta


class ActivitiesAPI:
	"""API operations for activity searches"""

	def __init__(self, client):
		"""Initialize with AMP client"""
		self.client = client

	def search(self, query: str, **params) -> Generator[Dict[str, Any], None, None]:
		"""
		Search for activities across all computers

		Args:
			query: Search query (SHA256, filename, URL, etc.)
			**params: Additional query parameters:
				- limit: Number of results
				- offset: Starting position
				- start_date: Start date for search
				- end_date: End date for search

		Yields:
			Activity records
		"""
		params['q'] = query
		for item in self.client.paginate('computers/activity', params):
			yield item

	def search_by_sha256(self, sha256: str, **params) -> Generator[Dict[str, Any], None, None]:
		"""
		Search for activity by file SHA256

		Args:
			sha256: File SHA256 hash
			**params: Additional query parameters

		Yields:
			Activity records
		"""
		return self.search(sha256, **params)

	def search_by_filename(self, filename: str, **params) -> Generator[Dict[str, Any], None, None]:
		"""
		Search for activity by filename

		Args:
			filename: Filename to search for
			**params: Additional query parameters

		Yields:
			Activity records
		"""
		return self.search(filename, **params)

	def search_by_url(self, url: str, **params) -> Generator[Dict[str, Any], None, None]:
		"""
		Search for activity by URL

		Args:
			url: URL to search for
			**params: Additional query parameters

		Yields:
			Activity records
		"""
		return self.search(url, **params)

	def find_computers_with_file(self, sha256: str) -> List[Dict[str, Any]]:
		"""
		Find all computers that have seen a specific file

		Args:
			sha256: File SHA256 hash

		Returns:
			List of computers with activity
		"""
		computers = {}
		for activity in self.search_by_sha256(sha256):
			guid = activity.get('connector_guid')
			if guid and guid not in computers:
				computers[guid] = {
					'connector_guid': guid,
					'hostname': activity.get('hostname', 'Unknown'),
					'first_seen': activity.get('date'),
					'activity_count': 1
				}
			elif guid:
				computers[guid]['activity_count'] += 1

		return list(computers.values())

	def get_file_trajectory(self, sha256: str, limit: int = 1000) -> Dict[str, Any]:
		"""
		Get complete trajectory for a file across all computers

		Args:
			sha256: File SHA256 hash
			limit: Maximum number of events to retrieve

		Returns:
			Dictionary with file trajectory information
		"""
		trajectory = {
			'sha256': sha256,
			'computers_affected': set(),
			'total_events': 0,
			'first_seen': None,
			'last_seen': None,
			'events_by_computer': {}
		}

		for activity in self.search_by_sha256(sha256, limit=limit):
			guid = activity.get('connector_guid')
			hostname = activity.get('hostname', 'Unknown')
			date = activity.get('date')

			# Track affected computers
			trajectory['computers_affected'].add(guid)
			trajectory['total_events'] += 1

			# Track timeline
			if not trajectory['first_seen'] or date < trajectory['first_seen']:
				trajectory['first_seen'] = date
			if not trajectory['last_seen'] or date > trajectory['last_seen']:
				trajectory['last_seen'] = date

			# Group events by computer
			if guid not in trajectory['events_by_computer']:
				trajectory['events_by_computer'][guid] = {
					'hostname': hostname,
					'events': []
				}

			trajectory['events_by_computer'][guid]['events'].append(activity)

		# Convert set to list for JSON serialization
		trajectory['computers_affected'] = list(trajectory['computers_affected'])

		return trajectory

	def search_lateral_movement(self, time_window: int = 3600) -> Generator[Dict[str, Any], None, None]:
		"""
		Search for potential lateral movement activity

		Args:
			time_window: Time window in seconds to correlate events

		Yields:
			Potential lateral movement indicators
		"""
		# Search for common lateral movement tools
		lateral_movement_indicators = [
			'psexec.exe',
			'wmic.exe',
			'powershell.exe -exec bypass',
			'net use',
			'reg add',
			'schtasks.exe'
		]

		results = {}

		for indicator in lateral_movement_indicators:
			for activity in self.search(indicator):
				key = f"{activity.get('connector_guid')}_{indicator}"
				if key not in results:
					results[key] = []
				results[key].append(activity)

		# Analyze results for patterns
		for key, activities in results.items():
			if len(activities) > 1:
				# Sort by date
				activities.sort(key=lambda x: x.get('date', ''))

				# Check for rapid succession
				for i in range(len(activities) - 1):
					time1 = datetime.fromisoformat(activities[i]['date'].replace('Z', '+00:00'))
					time2 = datetime.fromisoformat(activities[i + 1]['date'].replace('Z', '+00:00'))

					if (time2 - time1).total_seconds() <= time_window:
						yield {
							'type': 'potential_lateral_movement',
							'indicator': key.split('_')[1],
							'computer': activities[i].get('hostname'),
							'connector_guid': activities[i].get('connector_guid'),
							'events': [activities[i], activities[i + 1]]
						}