#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Custom exceptions for AMP Client
"""


class AMPError(Exception):
	"""Base exception for all AMP client errors"""
	pass


class AMPAuthenticationError(AMPError):
	"""Raised when authentication fails"""
	pass


class AMPRateLimitError(AMPError):
	"""Raised when rate limit is exceeded"""
	def __init__(self, message, retry_after=None):
		super().__init__(message)
		self.retry_after = retry_after


class AMPNotFoundError(AMPError):
	"""Raised when requested resource is not found"""
	pass


class AMPServerError(AMPError):
	"""Raised when server returns 5xx error"""
	pass


class AMPConfigError(AMPError):
	"""Raised when configuration is invalid"""
	pass