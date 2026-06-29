#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Analysis - Base class for offline analysis, malware triage, and reporting modules
"""

from core.framework.base_module import BaseModule, ModuleResult, normalize_module_result
from core.framework.failure import ProcedureError


class Analysis(BaseModule):
    """
    Base class for analysis modules.

    These modules perform offline or local analysis tasks such as:
    - Malware configuration extraction
    - Forensic artifact carving and timeline building
    - Firmware/binary inspection
    - Report generation from workspace data
    """

    TYPE_MODULE = "analysis"

    def __init__(self):
        super().__init__()

    def run(self):
        raise NotImplementedError("Analysis modules must implement the run() method")

    def _exploit(self):
        try:
            return normalize_module_result(self.run())
        except ProcedureError:
            return ModuleResult(success=False)
        except Exception:
            return ModuleResult(success=False)
