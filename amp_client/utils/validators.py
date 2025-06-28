#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Input validation utilities
"""

import re
from typing import Optional, List
from ipaddress import ip_address, ip_network, AddressValueError


class Validators:
	"""Input validation utilities"""

	@staticmethod
	def is_valid_sha256(hash_string: str) -> bool:
		"""Validate SHA256 hash format"""
		if not hash_string:
			return False
		pattern = r'^[a-fA-F0-9]{64}$'
		return bool(re.match(pattern, hash_string))

	@staticmethod
	def is_valid_sha1(hash_string: str) -> bool:
		"""Validate SHA1 hash format"""
		if not hash_string:
			return False
		pattern = r'^[a-fA-F0-9]{40}$'
		return bool(re.match(pattern, hash_string))

	@staticmethod
	def is_valid_md5(hash_string: str) -> bool:
		"""Validate MD5 hash format"""
		if not hash_string:
			return False
		pattern = r'^[a-fA-F0-9]{32}$'
		return bool(re.match(pattern, hash_string))

	@staticmethod
	def is_valid_guid(guid: str) -> bool:
		"""Validate GUID format"""
		if not guid:
			return False
		pattern = r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'
		return bool(re.match(pattern, guid))

	@staticmethod
	def is_valid_ip(ip: str) -> bool:
		"""Validate IP address"""
		try:
			ip_address(ip)
			return True
		except (AddressValueError, ValueError):
			return False

	@staticmethod
	def is_valid_cidr(cidr: str) -> bool:
		"""Validate CIDR notation"""
		try:
			ip_network(cidr)
			return True
		except (AddressValueError, ValueError):
			return False

	@staticmethod
	def is_valid_domain(domain: str) -> bool:
		"""Validate domain name"""
		if not domain or len(domain) > 253:
			return False

		# Remove trailing dot if present
		if domain.endswith('.'):
			domain = domain[:-1]

		# Check each label
		labels = domain.split('.')
		if len(labels) < 2:  # At least domain.tld required
			return False

		for label in labels:
			if not label or len(label) > 63:
				return False
			if label.startswith('-') or label.endswith('-'):
				return False
			if not all(c.isalnum() or c == '-' for c in label):
				return False

		return True

	@staticmethod
	def is_valid_url(url: str) -> bool:
		"""Validate URL format"""
		url_pattern = re.compile(
			r'^https?://'  # http:// or https://
			r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
			r'localhost|'  # localhost...
			r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
			r'(?::\d+)?'  # optional port
			r'(?:/?|[/?]\S+)$', re.IGNORECASE)
		return bool(url_pattern.match(url))

	@staticmethod
	def is_valid_port(port: int) -> bool:
		"""Validate port number"""
		return 0 < port <= 65535

	@staticmethod
	def sanitize_filename(filename: str) -> str:
		"""Sanitize filename for safe use"""
		# Remove path components
		filename = filename.replace('\\', '/').split('/')[-1]

		# Remove potentially dangerous characters
		invalid_chars = '<>:"|?*'
		for char in invalid_chars:
			filename = filename.replace(char, '_')

		# Limit length
		if len(filename) > 255:
			name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
			max_name_len = 255 - len(ext) - 1 if ext else 255
			filename = name[:max_name_len] + ('.' + ext if ext else '')

		return filename

	@staticmethod
	def validate_search_term(term: str, min_length: int = 3) -> Optional[str]:
		"""
		Validate and sanitize search term

		Args:
			term: Search term to validate
			min_length: Minimum required length

		Returns:
			Sanitized term or None if invalid
		"""
		if not term or len(term.strip()) < min_length:
			return None

		# Remove potentially dangerous characters for searches
		sanitized = re.sub(r'[^\w\s\-\.\@\:]', '', term)
		return sanitized.strip()


class HashIdentifier:
	"""Identify hash types"""

	@staticmethod
	def identify_hash_type(hash_string: str) -> Optional[str]:
		"""
		Identify the type of hash

		Args:
			hash_string: Hash to identify

		Returns:
			Hash type ('sha256', 'sha1', 'md5') or None
		"""
		if not hash_string:
			return None

		hash_string = hash_string.strip().lower()

		if Validators.is_valid_sha256(hash_string):
			return 'sha256'
		elif Validators.is_valid_sha1(hash_string):
			return 'sha1'
		elif Validators.is_valid_md5(hash_string):
			return 'md5'

		return None

	@staticmethod
	def is_hash(text: str) -> bool:
		"""Check if text is any type of hash"""
		return HashIdentifier.identify_hash_type(text) is not None


class LateralMovementDetector:
	"""Detect potential lateral movement patterns"""

	# Common lateral movement tools and techniques
	LATERAL_MOVEMENT_INDICATORS = [
		# Remote execution tools
		'psexec.exe', 'psexesvc.exe', 'paexec.exe',
		'wmic.exe', 'wmiexec.py', 'smbexec.py',
		'atexec.py', 'dcomexec.py',

		# PowerShell remoting
		'invoke-command', 'enter-pssession', 'new-pssession',
		'invoke-wmimethod', 'invoke-cimmethod',

		# Windows commands
		'net use', 'net session', 'net share',
		'schtasks /create', 'at.exe',
		'sc \\\\', 'reg add \\\\',

		# RDP
		'mstsc.exe', 'rdpclip.exe', 'tscon.exe',

		# SSH/SCP
		'ssh.exe', 'scp.exe', 'putty.exe', 'plink.exe',

		# Admin tools
		'crackmapexec', 'impacket', 'empire', 'covenant'
	]

	# Suspicious ports for lateral movement
	LATERAL_MOVEMENT_PORTS = {
		135: 'RPC/DCE',
		139: 'NetBIOS',
		445: 'SMB',
		3389: 'RDP',
		5985: 'WinRM HTTP',
		5986: 'WinRM HTTPS',
		22: 'SSH',
		23: 'Telnet',
		1433: 'MSSQL',
		3306: 'MySQL',
		5432: 'PostgreSQL'
	}

	@classmethod
	def is_lateral_movement_indicator(cls, text: str) -> bool:
		"""Check if text contains lateral movement indicators"""
		if not text:
			return False

		text_lower = text.lower()
		return any(indicator in text_lower for indicator in cls.LATERAL_MOVEMENT_INDICATORS)

	@classmethod
	def is_lateral_movement_port(cls, port: int) -> Optional[str]:
		"""Check if port is commonly used for lateral movement"""
		return cls.LATERAL_MOVEMENT_PORTS.get(port)