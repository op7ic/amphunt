#!/usr/bin/env python3
"""
Author: Jerzy 'Yuri' Kramarz (op7ic)
Copyright: See LICENSE file
Github: https://github.com/op7ic/amphunt
"""

"""
Data models for AMP Client
"""

from .computer import Computer, ComputerTrajectory, TrajectoryEvent
from .event import Event, EventType, NetworkEvent

__all__ = [
	"Computer",
	"ComputerTrajectory",
	"TrajectoryEvent",
	"Event",
	"EventType",
	"NetworkEvent"
]