# -*- coding: utf-8 -*-
"""Oracle TNS helpers (NSE oracle-tns-version / oracle-sid-brute)."""

from lib.scanner.oracle.detectors import probe_oracle_sid_brute, probe_oracle_tns_version

__all__ = ["probe_oracle_tns_version", "probe_oracle_sid_brute"]
