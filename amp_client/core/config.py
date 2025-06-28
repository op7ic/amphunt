#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Configuration management for AMP Client
"""

import os
import json
import configparser
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from .exceptions import AMPConfigError


@dataclass
class Config:
	"""Configuration for AMP Client"""
	client_id: Optional[str] = None
	api_key: Optional[str] = None
	domain: str = "api.amp.cisco.com"
	region: str = "nam"  # nam, eu, apjc
	verify_ssl: bool = True
	timeout: int = 30
	max_retries: int = 3
	retry_backoff: float = 1.0
	cache_enabled: bool = True
	cache_ttl: int = 300  # 5 minutes
	cache_backend: str = "memory"  # memory, redis
	cache_redis_url: Optional[str] = None
	rate_limit_buffer: int = 50  # Stop when this many requests remain

	# Regional domain mapping
	REGIONAL_DOMAINS: Dict[str, str] = field(default_factory=lambda: {
		"nam": "api.amp.cisco.com",
		"eu": "api.eu.amp.cisco.com",
		"apjc": "api.apjc.amp.cisco.com"
	})

	def __post_init__(self):
		"""Validate and set regional domain"""
		if self.region in self.REGIONAL_DOMAINS:
			self.domain = self.REGIONAL_DOMAINS[self.region]

	@classmethod
	def from_env(cls) -> "Config":
		"""Create config from environment variables"""
		return cls(
			client_id=os.getenv("AMP_CLIENT_ID"),
			api_key=os.getenv("AMP_API_KEY"),
			domain=os.getenv("AMP_DOMAIN", "api.amp.cisco.com"),
			region=os.getenv("AMP_REGION", "nam"),
			verify_ssl=os.getenv("AMP_VERIFY_SSL", "true").lower() == "true",
			timeout=int(os.getenv("AMP_TIMEOUT", "30")),
			max_retries=int(os.getenv("AMP_MAX_RETRIES", "3")),
			retry_backoff=float(os.getenv("AMP_RETRY_BACKOFF", "1.0")),
			cache_enabled=os.getenv("AMP_CACHE_ENABLED", "true").lower() == "true",
			cache_ttl=int(os.getenv("AMP_CACHE_TTL", "300")),
			cache_backend=os.getenv("AMP_CACHE_BACKEND", "memory"),
			cache_redis_url=os.getenv("AMP_CACHE_REDIS_URL"),
			rate_limit_buffer=int(os.getenv("AMP_RATE_LIMIT_BUFFER", "50"))
		)

	@classmethod
	def from_file(cls, path: str) -> "Config":
		"""Create config from file (JSON or INI format)"""
		path_obj = Path(path)
		if not path_obj.exists():
			raise AMPConfigError(f"Config file not found: {path}")

		if path_obj.suffix == ".json":
			return cls._from_json(path_obj)
		elif path_obj.suffix in [".ini", ".txt", ".conf"]:
			return cls._from_ini(path_obj)
		else:
			raise AMPConfigError(f"Unsupported config format: {path_obj.suffix}")

	@classmethod
	def _from_json(cls, path: Path) -> "Config":
		"""Load config from JSON file"""
		with open(path, 'r') as f:
			data = json.load(f)
		return cls(**data)

	@classmethod
	def _from_ini(cls, path: Path) -> "Config":
		"""Load config from INI file (backward compatibility)"""
		parser = configparser.ConfigParser()
		parser.read(path)

		# Support both [settings] and [api] sections for backward compatibility
		if 'settings' in parser:
			settings = parser['settings']
		elif 'api' in parser:
			settings = parser['api']
		else:
			raise AMPConfigError("Config file must have [settings] or [api] section")
		return cls(
			client_id=settings.get('client_id'),
			api_key=settings.get('api_key'),
			domain=settings.get('domainIP', 'api.amp.cisco.com'),
			region=settings.get('region', 'nam'),
			verify_ssl=settings.getboolean('verify_ssl', True),
			timeout=settings.getint('timeout', 30),
			max_retries=settings.getint('max_retries', 3),
			cache_enabled=settings.getboolean('cache_enabled', True),
			cache_ttl=settings.getint('cache_ttl', 300)
		)

	def validate(self):
		"""Validate configuration"""
		if not self.client_id:
			raise AMPConfigError("client_id is required")
		if not self.api_key:
			raise AMPConfigError("api_key is required")
		if not self.domain:
			raise AMPConfigError("domain is required")
		if self.timeout <= 0:
			raise AMPConfigError("timeout must be positive")
		if self.max_retries < 0:
			raise AMPConfigError("max_retries must be non-negative")
		if self.cache_ttl < 0:
			raise AMPConfigError("cache_ttl must be non-negative")
		if self.rate_limit_buffer < 0:
			raise AMPConfigError("rate_limit_buffer must be non-negative")