#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Backward-compatible alias for :class:`WlanCapture`."""

from lib.protocols.wlan.capture import WlanCapture, scapy_available

WlanLiveCapture = WlanCapture

__all__ = ["WlanCapture", "WlanLiveCapture", "scapy_available"]