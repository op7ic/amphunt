#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Authentication handling for AMP Client
"""

import base64
from typing import Optional, Tuple
from requests.auth import HTTPBasicAuth
try:
	import keyring
	KEYRING_AVAILABLE = True
except ImportError:
	KEYRING_AVAILABLE = False
	keyring = None
from .exceptions import AMPAuthenticationError


class AMPAuth(HTTPBasicAuth):
	"""Custom authentication handler for AMP API"""

	def __init__(self, client_id: str, api_key: str):
		"""Initialize authentication with client ID and API key"""
		if not client_id or not api_key:
			raise AMPAuthenticationError("Client ID and API key are required")
		super().__init__(client_id, api_key)
		self.client_id = client_id
		self.api_key = api_key

	def __call__(self, r):
		"""Apply authentication to request"""
		r.headers['Authorization'] = self.get_auth_header()
		return r

	def get_auth_header(self) -> str:
		"""Generate authorization header"""
		credentials = f"{self.client_id}:{self.api_key}"
		encoded = base64.b64encode(credentials.encode()).decode('ascii')
		return f"Basic {encoded}"


class SecureCredentialStore:
	"""Secure storage for API credentials using system keyring"""

	SERVICE_NAME = "cisco-amp-client"

	@classmethod
	def store_credentials(cls, client_id: str, api_key: str, profile: str = "default"):
		"""Store credentials securely in system keyring"""
		if not KEYRING_AVAILABLE:
			raise AMPAuthenticationError("Keyring not available - cannot store credentials securely")
		try:
			keyring.set_password(cls.SERVICE_NAME, f"{profile}_client_id", client_id)
			keyring.set_password(cls.SERVICE_NAME, f"{profile}_api_key", api_key)
		except Exception as e:
			raise AMPAuthenticationError(f"Failed to store credentials: {e}")

	@classmethod
	def get_credentials(cls, profile: str = "default") -> Tuple[Optional[str], Optional[str]]:
		"""Retrieve credentials from system keyring"""
		if not KEYRING_AVAILABLE:
			return None, None
		try:
			client_id = keyring.get_password(cls.SERVICE_NAME, f"{profile}_client_id")
			api_key = keyring.get_password(cls.SERVICE_NAME, f"{profile}_api_key")
			return client_id, api_key
		except Exception as e:
			raise AMPAuthenticationError(f"Failed to retrieve credentials: {e}")

	@classmethod
	def delete_credentials(cls, profile: str = "default"):
		"""Delete credentials from system keyring"""
		if not KEYRING_AVAILABLE:
			return
		try:
			keyring.delete_password(cls.SERVICE_NAME, f"{profile}_client_id")
			keyring.delete_password(cls.SERVICE_NAME, f"{profile}_api_key")
		except Exception:
			pass  # Ignore if credentials don't exist

	@classmethod
	def list_profiles(cls) -> list:
		"""List all stored credential profiles"""
		# This is a simplified implementation
		# In production, you might want to store profile names separately
		return ["default"]