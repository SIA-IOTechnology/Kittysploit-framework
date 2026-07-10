#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detection engineering helpers for KittySploit."""

from core.detection.pack_generator import DetectionPackGenerator
from core.detection.post_telemetry import enrich_edr_hypotheses, enrich_expected_logs, get_post_telemetry

__all__ = ["DetectionPackGenerator", "get_post_telemetry", "enrich_expected_logs", "enrich_edr_hypotheses"]
