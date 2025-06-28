#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Rate limiting utilities for AMP Client
"""

import time
import threading
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ..core.exceptions import AMPRateLimitError


@dataclass
class RateLimitInfo:
	"""Information about current rate limit status"""
	limit: int = 3000
	remaining: int = 3000
	reset: int = 0
	reset_date: Optional[datetime] = None

	@classmethod
	def from_headers(cls, headers: Dict[str, str]) -> "RateLimitInfo":
		"""Create RateLimitInfo from response headers"""
		return cls(
			limit=int(headers.get('X-RateLimit-Limit', 3000)),
			remaining=int(headers.get('X-RateLimit-Remaining', 3000)),
			reset=int(headers.get('X-RateLimit-Reset', 0)),
			reset_date=datetime.fromtimestamp(int(headers.get('X-RateLimit-Reset', 0)))
			if headers.get('X-RateLimit-Reset') else None
		)

	@property
	def is_exhausted(self) -> bool:
		"""Check if rate limit is exhausted"""
		return self.remaining <= 0

	@property
	def seconds_until_reset(self) -> int:
		"""Calculate seconds until rate limit reset"""
		if self.reset_date:
			delta = self.reset_date - datetime.now()
			return max(0, int(delta.total_seconds()))
		return 0


class RateLimiter:
	"""Thread-safe rate limiter with intelligent throttling"""

	def __init__(self, buffer: int = 50):
		"""
		Initialize rate limiter

		Args:
			buffer: Number of requests to keep in reserve
		"""
		self.buffer = buffer
		self.info = RateLimitInfo()
		self._lock = threading.Lock()
		self._request_times: list = []
		self._window_size = 3600  # 1 hour window

	def update_from_headers(self, headers: Dict[str, str]):
		"""Update rate limit info from response headers"""
		with self._lock:
			self.info = RateLimitInfo.from_headers(headers)

	def check_limit(self) -> bool:
		"""
		Check if request can be made within rate limits

		Returns:
			True if request can be made, False otherwise
		"""
		with self._lock:
			# Clean old requests from tracking
			self._clean_old_requests()

			# Check if we're approaching the limit
			if self.info.remaining <= self.buffer:
				return False

			# Track this request
			self._request_times.append(time.time())
			return True

	def wait_if_needed(self):
		"""Wait if rate limit is exhausted or approaching limit"""
		with self._lock:
			if self.info.is_exhausted:
				wait_time = self.info.seconds_until_reset + 5
				raise AMPRateLimitError(
					f"Rate limit exhausted. Retry after {wait_time} seconds",
					retry_after=wait_time
				)

			if self.info.remaining <= self.buffer:
				# Intelligent backoff based on remaining quota
				wait_time = self._calculate_backoff()
				if wait_time > 0:
					time.sleep(wait_time)

	def _calculate_backoff(self) -> float:
		"""Calculate backoff time based on current rate"""
		if not self._request_times:
			return 0

		# Calculate request rate
		current_time = time.time()
		recent_requests = [t for t in self._request_times 
						  if current_time - t < 60]  # Last minute

		if len(recent_requests) < 2:
			return 0

		# If making requests too quickly, slow down
		rate = len(recent_requests) / 60.0  # Requests per second
		if rate > 0.5:  # More than 30 requests per minute
			return min(2.0, 1.0 / rate)

		return 0

	def _clean_old_requests(self):
		"""Remove request times older than window size"""
		current_time = time.time()
		self._request_times = [t for t in self._request_times 
							  if current_time - t < self._window_size]

	def get_stats(self) -> Dict[str, Any]:
		"""Get current rate limiter statistics"""
		with self._lock:
			return {
				"limit": self.info.limit,
				"remaining": self.info.remaining,
				"reset_in": self.info.seconds_until_reset,
				"buffer": self.buffer,
				"recent_requests": len(self._request_times),
				"can_request": self.info.remaining > self.buffer
			}


class TokenBucket:
	"""Token bucket algorithm for rate limiting"""

	def __init__(self, rate: float, capacity: int):
		"""
		Initialize token bucket

		Args:
			rate: Number of tokens added per second
			capacity: Maximum number of tokens
		"""
		self.rate = rate
		self.capacity = capacity
		self.tokens = capacity
		self.last_update = time.time()
		self._lock = threading.Lock()

	def consume(self, tokens: int = 1) -> bool:
		"""
		Try to consume tokens

		Args:
			tokens: Number of tokens to consume

		Returns:
			True if tokens were consumed, False otherwise
		"""
		with self._lock:
			self._refill()

			if self.tokens >= tokens:
				self.tokens -= tokens
				return True
			return False

	def _refill(self):
		"""Refill tokens based on elapsed time"""
		current_time = time.time()
		elapsed = current_time - self.last_update

		# Add tokens based on rate
		self.tokens = min(
			self.capacity,
			self.tokens + (elapsed * self.rate)
		)
		self.last_update = current_time