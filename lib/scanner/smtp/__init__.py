# -*- coding: utf-8 -*-
"""SMTP scanner helpers (NSE smtp-open-relay / smtp-commands)."""

from lib.scanner.smtp.detectors import probe_smtp_commands, probe_smtp_open_relay

__all__ = ["probe_smtp_commands", "probe_smtp_open_relay"]
