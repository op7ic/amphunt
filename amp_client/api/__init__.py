#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
API modules for AMP Client
"""

from .computers import ComputersAPI
from .events import EventsAPI
from .activities import ActivitiesAPI

__all__ = [
	"ComputersAPI",
	"EventsAPI",
	"ActivitiesAPI"
]