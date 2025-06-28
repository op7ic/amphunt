#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Event related API operations
"""

from typing import Optional, Dict, Any, List, Generator, Union
from datetime import datetime
from ..models.event import Event, EventType


class EventsAPI:
	"""API operations for events"""

	def __init__(self, client):
		"""Initialize with AMP client"""
		self.client = client

	def list(self, **params) -> Generator[Event, None, None]:
		"""
		List events

		Args:
			**params: Query parameters:
				- detection_sha256: SHA256 of detection
				- application_sha256: SHA256 of application
				- connector_guid: Specific computer GUID
				- group_guid: Group GUID
				- start_date: Start date (ISO format)
				- end_date: End date (ISO format)
				- event_type: Event type ID or name
				- limit: Number of results
				- offset: Starting position

		Yields:
			Event objects
		"""
		# Convert event type names to IDs if needed
		if 'event_type' in params and isinstance(params['event_type'], str):
			params['event_type'] = EventType.get_id(params['event_type'])

		# Handle multiple event types
		if 'event_types' in params:
			if isinstance(params['event_types'], list):
				params['event_type[]'] = [
					EventType.get_id(et) if isinstance(et, str) else et
					for et in params['event_types']
				]
				del params['event_types']

		for item in self.client.paginate('events', params):
			yield Event.from_dict(item)

	def get(self, event_id: str) -> Event:
		"""
		Get specific event by ID

		Args:
			event_id: Event ID

		Returns:
			Event object
		"""
		data = self.client.get(f'events/{event_id}')
		return Event.from_dict(data['data'])

	def search_by_type(self, event_type: Union[str, int], **params) -> Generator[Event, None, None]:
		"""
		Search events by type

		Args:
			event_type: Event type name or ID
			**params: Additional query parameters

		Yields:
			Event objects
		"""
		params['event_type'] = event_type
		return self.list(**params)

	def search_network_events(self, connector_guid: Optional[str] = None, **params) -> Generator[Event, None, None]:
		"""
		Search for network events (NFM)

		Args:
			connector_guid: Optional computer GUID
			**params: Additional query parameters

		Yields:
			Network event objects
		"""
		params['event_type'] = EventType.NFM
		if connector_guid:
			params['connector_guid'] = connector_guid
		return self.list(**params)

	def search_threat_events(self, **params) -> Generator[Event, None, None]:
		"""
		Search for threat detection events

		Args:
			**params: Query parameters

		Yields:
			Threat event objects
		"""
		threat_types = [
			EventType.THREAT_DETECTED,
			EventType.THREAT_QUARANTINED,
			EventType.MALICIOUS_ACTIVITY
		]
		params['event_types'] = threat_types
		return self.list(**params)

	def search_execution_events(self, sha256: Optional[str] = None, **params) -> Generator[Event, None, None]:
		"""
		Search for file execution events

		Args:
			sha256: Optional file SHA256
			**params: Additional query parameters

		Yields:
			Execution event objects
		"""
		execution_types = [
			EventType.EXECUTED,
			EventType.EXECUTION_BLOCKED
		]
		params['event_types'] = execution_types
		if sha256:
			params['application_sha256'] = sha256
		return self.list(**params)

	def get_event_types(self) -> List[Dict[str, Any]]:
		"""
		Get list of all event types

		Returns:
			List of event type definitions
		"""
		data = self.client.get('event_types')
		return data['data']

	def export_to_csv(self, events: List[Event], output_file: str):
		"""
		Export events to CSV file

		Args:
			events: List of events to export
			output_file: Output CSV filename
		"""
		import csv

		with open(output_file, 'w', newline='', encoding='utf-8') as f:
			writer = csv.DictWriter(f, fieldnames=[
				'timestamp', 'event_type', 'hostname', 'connector_guid',
				'severity', 'file_name', 'file_path', 'file_sha256',
				'detection_name', 'disposition', 'isolation_status'
			])
			writer.writeheader()

			for event in events:
				row = {
					'timestamp': event.date,
					'event_type': event.event_type,
					'hostname': event.computer.get('hostname', '') if event.computer else '',
					'connector_guid': event.connector_guid,
					'severity': event.severity,
				}

				if event.file:
					row.update({
						'file_name': event.file.get('file_name', ''),
						'file_path': event.file.get('file_path', ''),
						'file_sha256': event.file.get('identity', {}).get('sha256', ''),
						'disposition': event.file.get('disposition', '')
					})

				if event.detection:
					row['detection_name'] = event.detection.get('name', '')

				writer.writerow(row)