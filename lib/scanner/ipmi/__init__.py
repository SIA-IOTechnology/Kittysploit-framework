# -*- coding: utf-8 -*-
"""IPMI / RMCP scanners (NSE ipmi-version / ipmi-cipher-zero)."""

from lib.scanner.ipmi.detectors import probe_ipmi_cipher_zero, probe_ipmi_version

__all__ = ["probe_ipmi_cipher_zero", "probe_ipmi_version"]
