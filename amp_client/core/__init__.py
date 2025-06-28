#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Core modules for AMP Client
"""

from .client import AMPClient
from .config import Config
from .auth import AMPAuth, SecureCredentialStore
from .exceptions import (
	AMPError,
	AMPAuthenticationError,
	AMPRateLimitError,
	AMPNotFoundError,
	AMPServerError,
	AMPConfigError
)

__all__ = [
	"AMPClient",
	"Config",
	"AMPAuth",
	"SecureCredentialStore",
	"AMPError",
	"AMPAuthenticationError",
	"AMPRateLimitError",
	"AMPNotFoundError",
	"AMPServerError",
	"AMPConfigError"
]