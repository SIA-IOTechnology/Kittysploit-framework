#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KittySploit SQLi engine — minimal-request detection and blind extraction.

Replaces spray-and-pray payload lists with baseline-first, budget-aware probes.
"""

from .constants import DETECTION_CONFIDENCE, SQLI_ERROR_TOKENS, TECHNIQUE_LABELS
from .engine import SqliEngine, SqliScanResult
from .fingerprint import contains_sqli_error, evidence_snippet, fingerprint_dbms, match_sqli_error
from .oracle import HttpParameterOracle, ProbeResponse, SqliOracle
from .techniques import TechniqueHit, boolean_evidence, probe_error, technique_label
from .constants import TECHNIQUE_TO_DETECTION_KIND, TECHNIQUE_TO_RESULT_NAME

__all__ = [
    "DETECTION_CONFIDENCE",
    "SQLI_ERROR_TOKENS",
    "TECHNIQUE_LABELS",
    "TECHNIQUE_TO_DETECTION_KIND",
    "TECHNIQUE_TO_RESULT_NAME",
    "HttpParameterOracle",
    "ProbeResponse",
    "SqliEngine",
    "SqliOracle",
    "SqliScanResult",
    "TechniqueHit",
    "boolean_evidence",
    "contains_sqli_error",
    "evidence_snippet",
    "fingerprint_dbms",
    "match_sqli_error",
    "probe_error",
    "technique_label",
]
