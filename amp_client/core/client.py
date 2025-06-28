#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Core AMP API Client
"""

import time
import logging
from typing import Optional, Dict, Any, List, Generator
from urllib.parse import urljoin, urlparse
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import requests_cache

from .config import Config
from .auth import AMPAuth, SecureCredentialStore
from .exceptions import (
	AMPError, AMPAuthenticationError, AMPRateLimitError,
	AMPNotFoundError, AMPServerError
)
from ..utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class AMPClient:
	"""Main client for interacting with Cisco AMP API"""

	def __init__(self, config: Optional[Config] = None, **kwargs):
		"""
		Initialize AMP client

		Args:
			config: Configuration object
			**kwargs: Override config parameters
		"""
		# Load config
		self.config = config or Config()

		# Override config with kwargs
		for key, value in kwargs.items():
			if hasattr(self.config, key):
				setattr(self.config, key, value)

		# Validate config
		self.config.validate()

		# Initialize components
		self._setup_session()
		self._setup_cache()
		self._setup_auth()
		self.rate_limiter = RateLimiter(buffer=self.config.rate_limit_buffer)

		# API endpoints will be initialized lazily via properties

		logger.info(f"AMP Client initialized for {self.config.domain}")

	def _setup_session(self):
		"""Setup requests session with retry strategy"""
		self.session = requests.Session()

		# Configure retry strategy
		retry_strategy = Retry(
			total=self.config.max_retries,
			backoff_factor=self.config.retry_backoff,
			status_forcelist=[429, 500, 502, 503, 504],
			allowed_methods=["GET", "POST", "PUT", "DELETE"]
		)

		adapter = HTTPAdapter(
			max_retries=retry_strategy,
			pool_connections=10,
			pool_maxsize=100
		)

		self.session.mount("https://", adapter)
		self.session.mount("http://", adapter)

		# Set default timeout
		self.session.timeout = self.config.timeout

		# Disable SSL warnings if configured
		if not self.config.verify_ssl:
			import urllib3
			urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
			self.session.verify = False

	def _setup_auth(self):
		"""Setup authentication"""
		# Try to get credentials from secure store if not provided
		if not self.config.client_id or not self.config.api_key:
			client_id, api_key = SecureCredentialStore.get_credentials()
			self.config.client_id = self.config.client_id or client_id
			self.config.api_key = self.config.api_key or api_key

		self.auth = AMPAuth(self.config.client_id, self.config.api_key)
		self.session.auth = self.auth

	def _setup_cache(self):
		"""Setup caching if enabled"""
		if self.config.cache_enabled:
			if self.config.cache_backend == "memory":
				self.session = requests_cache.CachedSession(
					cache_name='amp_cache',
					backend='memory',
					expire_after=self.config.cache_ttl,
					allowable_methods=['GET'],
					allowable_codes=[200]
				)
			elif self.config.cache_backend == "redis" and self.config.cache_redis_url:
				requests_cache.install_cache(
					cache_name='amp_cache',
					backend='redis',
					expire_after=self.config.cache_ttl,
					connection=self.config.cache_redis_url,
					allowable_methods=['GET'],
					allowable_codes=[200],
					session_factory=lambda: self.session
				)

	def _build_url(self, endpoint: str) -> str:
		"""Build full URL for endpoint"""
		base_url = f"https://{self.config.domain}/v1/"
		return urljoin(base_url, endpoint.lstrip('/'))

	def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
		"""Handle API response and errors"""
		# Update rate limiter from headers
		self.rate_limiter.update_from_headers(response.headers)

		# Handle different status codes
		if response.status_code == 200:
			return response.json()
		elif response.status_code == 401:
			raise AMPAuthenticationError("Authentication failed: Invalid credentials")
		elif response.status_code == 404:
			raise AMPNotFoundError(f"Resource not found: {response.url}")
		elif response.status_code == 429:
			retry_after = int(response.headers.get('Retry-After', 60))
			raise AMPRateLimitError(
				"Rate limit exceeded",
				retry_after=retry_after
			)
		elif response.status_code >= 500:
			raise AMPServerError(f"Server error: {response.status_code}")
		else:
			response.raise_for_status()

	def request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
		"""
		Make authenticated request to AMP API

		Args:
			method: HTTP method
			endpoint: API endpoint
			**kwargs: Additional request parameters

		Returns:
			Response data
		"""
		# Check rate limit
		self.rate_limiter.wait_if_needed()

		# Build URL
		url = self._build_url(endpoint)

		# Set timeout if not provided
		if 'timeout' not in kwargs:
			kwargs['timeout'] = self.config.timeout

		# Make request
		logger.debug(f"{method} {url}")
		response = self.session.request(method, url, **kwargs)

		# Handle response
		return self._handle_response(response)

	def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
		"""Make GET request"""
		return self.request('GET', endpoint, params=params)

	def post(self, endpoint: str, json: Optional[Dict] = None) -> Dict[str, Any]:
		"""Make POST request"""
		return self.request('POST', endpoint, json=json)

	def put(self, endpoint: str, json: Optional[Dict] = None) -> Dict[str, Any]:
		"""Make PUT request"""
		return self.request('PUT', endpoint, json=json)

	def delete(self, endpoint: str) -> Dict[str, Any]:
		"""Make DELETE request"""
		return self.request('DELETE', endpoint)

	def paginate(self, endpoint: str, params: Optional[Dict] = None) -> Generator[Dict, None, None]:
		"""
		Paginate through API results

		Args:
			endpoint: API endpoint
			params: Query parameters

		Yields:
			Individual items from paginated results
		"""
		next_url = self._build_url(endpoint)

		while next_url:
			# Make request
			if urlparse(next_url).netloc:
				# Full URL provided
				response = self.session.get(next_url, params=params, timeout=self.config.timeout)
			else:
				# Relative URL
				response = self.get(next_url, params=params)

			data = self._handle_response(response)

			# Yield items
			for item in data.get('data', []):
				yield item

			# Get next page URL
			next_url = data.get('metadata', {}).get('links', {}).get('next')
			params = None  # Clear params for subsequent requests

	def get_all(self, endpoint: str, params: Optional[Dict] = None) -> List[Dict]:
		"""Get all results from paginated endpoint"""
		return list(self.paginate(endpoint, params))

	def __enter__(self):
		"""Context manager entry"""
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		"""Context manager exit"""
		self.close()

	def close(self):
		"""Close client and cleanup resources"""
		self.session.close()

	# Convenience properties for API endpoints
	@property
	def computers(self):
		"""Access computer-related endpoints"""
		if not hasattr(self, '_computers'):
			from ..api.computers import ComputersAPI
			self._computers = ComputersAPI(self)
		return self._computers

	@property
	def events(self):
		"""Access event-related endpoints"""
		if not hasattr(self, '_events'):
			from ..api.events import EventsAPI
			self._events = EventsAPI(self)
		return self._events

	@property
	def activities(self):
		"""Access activity-related endpoints"""
		if not hasattr(self, '_activities'):
			from ..api.activities import ActivitiesAPI
			self._activities = ActivitiesAPI(self)
		return self._activities