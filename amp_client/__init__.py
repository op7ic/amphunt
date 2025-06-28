#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Cisco AMP for Endpoints API Client Library

A modern Python library for interacting with Cisco AMP for Endpoints API
with built-in rate limiting, caching, and error handling.
"""

from .core.client import AMPClient
from .core.config import Config
from .core.exceptions import (
	AMPError,
	AMPAuthenticationError,
	AMPRateLimitError,
	AMPNotFoundError,
	AMPServerError
)

__version__ = "1.0.0"
__all__ = [
	"AMPClient",
	"Config",
	"AMPError",
	"AMPAuthenticationError",
	"AMPRateLimitError",
	"AMPNotFoundError",
	"AMPServerError"
]