#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Computer/Endpoint data models
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone


@dataclass
class Computer:
	"""Represents an AMP endpoint/computer"""
	connector_guid: str
	hostname: str
	active: bool = True
	connector_version: Optional[str] = None
	operating_system: Optional[str] = None
	internal_ips: List[str] = field(default_factory=list)
	external_ip: Optional[str] = None
	group_guid: Optional[str] = None
	install_date: Optional[datetime] = None
	network_addresses: List[Dict[str, Any]] = field(default_factory=list)
	policy: Optional[Dict[str, Any]] = None
	links: Dict[str, str] = field(default_factory=dict)

	@classmethod
	def from_dict(cls, data: Dict[str, Any]) -> "Computer":
		"""Create Computer from API response"""
		return cls(
			connector_guid=data['connector_guid'],
			hostname=data['hostname'],
			active=data.get('active', True),
			connector_version=data.get('connector_version'),
			operating_system=data.get('operating_system'),
			internal_ips=data.get('internal_ips', []),
			external_ip=data.get('external_ip'),
			group_guid=data.get('group_guid'),
			install_date=datetime.fromisoformat(data['install_date'].replace('Z', '+00:00'))
			if data.get('install_date') else None,
			network_addresses=data.get('network_addresses', []),
			policy=data.get('policy'),
			links=data.get('links', {})
		)

	def to_dict(self) -> Dict[str, Any]:
		"""Convert to dictionary"""
		data = {
			'connector_guid': self.connector_guid,
			'hostname': self.hostname,
			'active': self.active,
			'connector_version': self.connector_version,
			'operating_system': self.operating_system,
			'internal_ips': self.internal_ips,
			'external_ip': self.external_ip,
			'group_guid': self.group_guid,
			'network_addresses': self.network_addresses,
			'policy': self.policy,
			'links': self.links
		}

		if self.install_date:
			data['install_date'] = self.install_date.isoformat()

		return data

	@property
	def primary_ip(self) -> Optional[str]:
		"""Get primary internal IP address"""
		return self.internal_ips[0] if self.internal_ips else None

	@property
	def is_isolated(self) -> bool:
		"""Check if computer is isolated"""
		# This would need to be determined from policy or separate API call
		return False

	def __str__(self) -> str:
		return f"{self.hostname} ({self.connector_guid})"


@dataclass
class TrajectoryEvent:
	"""Represents a single trajectory event"""
	id: Optional[str]
	timestamp: datetime
	event_type: str
	event_type_id: Optional[int] = None
	detection: Optional[Dict[str, Any]] = None
	file: Optional[Dict[str, Any]] = None
	network_info: Optional[Dict[str, Any]] = None

	@classmethod  
	def _parse_timestamp(cls, timestamp_data) -> datetime:
		"""Parse timestamp from various formats"""
		if isinstance(timestamp_data, int):
			# Unix timestamp
			return datetime.fromtimestamp(timestamp_data, tz=timezone.utc)
		elif isinstance(timestamp_data, str):
			# ISO format string
			if '+' in timestamp_data:
				return datetime.fromisoformat(timestamp_data.replace('+00:00', '+00:00'))
			else:
				return datetime.fromisoformat(timestamp_data + '+00:00')
		else:
			# Fallback to current time
			return datetime.now(tz=timezone.utc)

	@classmethod
	def from_dict(cls, data: Dict[str, Any]) -> "TrajectoryEvent":
		"""Create TrajectoryEvent from API response"""
		return cls(
			id=data.get('id'),
			timestamp=cls._parse_timestamp(data['timestamp']),
			event_type=data['event_type'],
			event_type_id=data.get('event_type_id'),
			detection=data.get('detection'),
			file=data.get('file'),
			network_info=data.get('network_info')
		)

	@property
	def is_network_event(self) -> bool:
		"""Check if this is a network event"""
		return str(self.event_type) == 'NFM' or self.network_info is not None

	@property
	def is_threat_event(self) -> bool:
		"""Check if this is a threat detection event"""
		event_type_str = str(self.event_type) if self.event_type else ""
		return 'Threat' in event_type_str or self.detection is not None

	@property
	def file_sha256(self) -> Optional[str]:
		"""Get file SHA256 if available"""
		if self.file and 'identity' in self.file:
			return self.file['identity'].get('sha256')
		return None


@dataclass
class ComputerTrajectory:
	"""Represents trajectory data for a computer"""
	computer: Computer
	events: List[TrajectoryEvent] = field(default_factory=list)

	@classmethod
	def from_dict(cls, data: Dict[str, Any]) -> "ComputerTrajectory":
		"""Create ComputerTrajectory from API response"""
		return cls(
			computer=Computer.from_dict(data['computer']),
			events=[TrajectoryEvent.from_dict(event) for event in data.get('events', [])]
		)

	def filter_by_type(self, event_type: str) -> List[TrajectoryEvent]:
		"""Filter events by type"""
		return [event for event in self.events if event.event_type == event_type]

	def get_network_events(self) -> List[TrajectoryEvent]:
		"""Get all network events"""
		return [event for event in self.events if event.is_network_event]

	def get_threat_events(self) -> List[TrajectoryEvent]:
		"""Get all threat events"""
		return [event for event in self.events if event.is_threat_event]

	def get_file_events(self, sha256: Optional[str] = None) -> List[TrajectoryEvent]:
		"""Get file-related events, optionally filtered by SHA256"""
		file_events = [event for event in self.events if event.file]
		if sha256:
			file_events = [event for event in file_events if event.file_sha256 == sha256]
		return file_events