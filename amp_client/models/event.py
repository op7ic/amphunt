#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Event data models
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import IntEnum


class EventType(IntEnum):
	"""Event type IDs"""
	# File events
	CREATED = 107
	EXECUTED = 1107
	MOVED = 108
	DELETED = 109

	# Threat events
	THREAT_DETECTED = 1090
	THREAT_QUARANTINED = 553648143
	QUARANTINE_FAILURE = 2164260880
	MALICIOUS_ACTIVITY = 1003
	EXECUTION_BLOCKED = 2164260893

	# Network events
	NFM = 553648147  # Network File Move
	DFC_THREAT = 1004  # Device Flow Correlation

	# System events
	SCAN_STARTED = 554696714
	SCAN_COMPLETED = 554696715
	POLICY_UPDATE = 553648170

	# Cloud IOC
	CLOUD_IOC = 1107296272

	@classmethod
	def get_name(cls, event_id: int) -> str:
		"""Get event type name from ID"""
		for name, value in cls.__members__.items():
			if value == event_id:
				return name.replace('_', ' ').title()
		return f"Unknown ({event_id})"

	@classmethod
	def get_id(cls, name: str) -> int:
		"""Get event type ID from name"""
		# Try exact match first
		name_upper = name.upper().replace(' ', '_')
		if hasattr(cls, name_upper):
			return getattr(cls, name_upper)

		# Try fuzzy match
		for member_name, value in cls.__members__.items():
			if name.upper() in member_name:
				return value

		raise ValueError(f"Unknown event type: {name}")


@dataclass
class Event:
	"""Represents an AMP event"""
	id: int
	date: str
	event_type: str
	event_type_id: int
	connector_guid: str
	computer: Optional[Dict[str, Any]] = None
	file: Optional[Dict[str, Any]] = None
	detection: Optional[Dict[str, Any]] = None
	network_info: Optional[Dict[str, Any]] = None
	scan: Optional[Dict[str, Any]] = None
	severity: Optional[str] = None
	cloud_ioc: Optional[Dict[str, Any]] = None

	@classmethod
	def from_dict(cls, data: Dict[str, Any]) -> "Event":
		"""Create Event from API response"""
		return cls(
			id=data['id'],
			date=data['date'],
			event_type=data['event_type'],
			event_type_id=data['event_type_id'],
			connector_guid=data['connector_guid'],
			computer=data.get('computer'),
			file=data.get('file'),
			detection=data.get('detection'),
			network_info=data.get('network_info'),
			scan=data.get('scan'),
			severity=data.get('severity'),
			cloud_ioc=data.get('cloud_ioc')
		)

	@property
	def timestamp(self) -> datetime:
		"""Get event timestamp as datetime"""
		return datetime.fromisoformat(self.date.replace('Z', '+00:00'))

	@property
	def hostname(self) -> Optional[str]:
		"""Get hostname if available"""
		return self.computer.get('hostname') if self.computer else None

	@property
	def file_sha256(self) -> Optional[str]:
		"""Get file SHA256 if available"""
		if self.file and 'identity' in self.file:
			return self.file['identity'].get('sha256')
		return None

	@property
	def file_path(self) -> Optional[str]:
		"""Get file path if available"""
		return self.file.get('file_path') if self.file else None

	@property
	def file_name(self) -> Optional[str]:
		"""Get file name if available"""
		return self.file.get('file_name') if self.file else None

	@property
	def is_malicious(self) -> bool:
		"""Check if event indicates malicious activity"""
		malicious_types = [
			EventType.THREAT_DETECTED,
			EventType.THREAT_QUARANTINED,
			EventType.MALICIOUS_ACTIVITY,
			EventType.EXECUTION_BLOCKED,
			EventType.DFC_THREAT
		]
		return self.event_type_id in malicious_types

	@property
	def is_network_event(self) -> bool:
		"""Check if this is a network event"""
		return self.event_type_id in [EventType.NFM, EventType.DFC_THREAT] or self.network_info is not None

	def get_network_details(self) -> Optional[Dict[str, Any]]:
		"""Get network event details"""
		if not self.network_info:
			return None

		details = {
			'local_ip': self.network_info.get('local_ip'),
			'local_port': self.network_info.get('local_port'),
			'remote_ip': self.network_info.get('remote_ip'),
			'remote_port': self.network_info.get('remote_port'),
		}

		if 'nfm' in self.network_info:
			details.update({
				'direction': self.network_info['nfm'].get('direction'),
				'protocol': self.network_info['nfm'].get('protocol')
			})

		if 'dirty_url' in self.network_info:
			details['url'] = self.network_info['dirty_url']

		return details

	def __str__(self) -> str:
		return f"{self.event_type} on {self.hostname or self.connector_guid} at {self.date}"


@dataclass
class NetworkEvent(Event):
	"""Specialized network event with additional properties"""

	@property
	def local_address(self) -> Optional[str]:
		"""Get local IP:port"""
		if self.network_info:
			return f"{self.network_info.get('local_ip')}:{self.network_info.get('local_port')}"
		return None

	@property
	def remote_address(self) -> Optional[str]:
		"""Get remote IP:port"""
		if self.network_info:
			return f"{self.network_info.get('remote_ip')}:{self.network_info.get('remote_port')}"
		return None

	@property
	def direction(self) -> Optional[str]:
		"""Get connection direction"""
		if self.network_info and 'nfm' in self.network_info:
			direction = self.network_info['nfm'].get('direction', '')
			if 'Outgoing' in direction:
				return 'outbound'
			elif 'Incoming' in direction:
				return 'inbound'
		return None

	@property
	def protocol(self) -> Optional[str]:
		"""Get network protocol"""
		if self.network_info and 'nfm' in self.network_info:
			return self.network_info['nfm'].get('protocol')
		return None