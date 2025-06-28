#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Computer/Endpoint related API operations
"""

from typing import Optional, Dict, Any, List, Generator
from ..models.computer import Computer, ComputerTrajectory


class ComputersAPI:
	"""API operations for computers/endpoints"""

	def __init__(self, client):
		"""Initialize with AMP client"""
		self.client = client

	def list(self, **params) -> Generator[Computer, None, None]:
		"""
		List all computers

		Args:
			**params: Query parameters (limit, offset, etc.)

		Yields:
			Computer objects
		"""
		for item in self.client.paginate('computers', params):
			yield Computer.from_dict(item)

	def get(self, connector_guid: str) -> Computer:
		"""
		Get specific computer by GUID

		Args:
			connector_guid: Computer's connector GUID

		Returns:
			Computer object
		"""
		data = self.client.get(f'computers/{connector_guid}')
		return Computer.from_dict(data['data'])

	def get_trajectory(self, connector_guid: str, **params) -> ComputerTrajectory:
		"""
		Get trajectory for specific computer

		Args:
			connector_guid: Computer's connector GUID
			**params: Query parameters (limit, q, etc.)

		Returns:
			ComputerTrajectory object
		"""
		data = self.client.get(f'computers/{connector_guid}/trajectory', params)
		return ComputerTrajectory.from_dict(data['data'])

	def search_by_name(self, hostname: str) -> List[Computer]:
		"""
		Search computers by hostname

		Args:
			hostname: Hostname to search for

		Returns:
			List of matching computers
		"""
		return list(self.list(hostname=hostname))

	def search_by_ip(self, ip: str, ip_type: str = 'internal') -> List[Computer]:
		"""
		Search computers by IP address

		Args:
			ip: IP address to search for
			ip_type: Type of IP ('internal' or 'external')

		Returns:
			List of matching computers
		"""
		params = {f'{ip_type}_ip': ip}
		return list(self.list(**params))

	def get_activity(self, q: str, **params) -> Generator[Dict[str, Any], None, None]:
		"""
		Search for computer activity

		Args:
			q: Search query (SHA256, filename, etc.)
			**params: Additional query parameters

		Yields:
			Activity records
		"""
		params['q'] = q
		for item in self.client.paginate('computers/activity', params):
			yield item

	def move_to_group(self, connector_guid: str, group_guid: str) -> Dict[str, Any]:
		"""
		Move computer to different group

		Args:
			connector_guid: Computer's connector GUID
			group_guid: Target group GUID

		Returns:
			API response
		"""
		return self.client.patch(
			f'computers/{connector_guid}',
			json={'group_guid': group_guid}
		)

	def isolate(self, connector_guid: str) -> Dict[str, Any]:
		"""
		Isolate computer from network

		Args:
			connector_guid: Computer's connector GUID

		Returns:
			API response
		"""
		return self.client.put(f'computers/{connector_guid}/isolation')

	def unisolate(self, connector_guid: str) -> Dict[str, Any]:
		"""
		Remove computer from isolation

		Args:
			connector_guid: Computer's connector GUID

		Returns:
			API response
		"""
		return self.client.delete(f'computers/{connector_guid}/isolation')

	def delete(self, connector_guid: str) -> Dict[str, Any]:
		"""
		Delete computer from AMP

		Args:
			connector_guid: Computer's connector GUID

		Returns:
			API response
		"""
		return self.client.delete(f'computers/{connector_guid}')