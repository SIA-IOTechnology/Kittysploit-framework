#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Simple contextual bandit multiplier for module ranking."""

from __future__ import annotations

import math
from typing import Any, Mapping, Optional


def bandit_multiplier(
    store: Any,
    module_path: str,
    context_fingerprint: str,
    *,
    exploration: float = 0.35,
) -> float:
    if store is None or not module_path or not context_fingerprint:
        return 1.0
    stats = store.bandit_stats(module_path, context_fingerprint)
    successes = float(stats.get("successes", 0) or 0)
    failures = float(stats.get("failures", 0) or 0)
    samples = successes + failures
    if samples < 2.0:
        return 1.0
    rate = successes / max(1.0, samples)
    bonus = (rate - 0.5) * min(0.42, 0.12 + samples * 0.015)
    ucb = exploration * math.sqrt(math.log(max(2.0, samples + 1.0)) / max(1.0, samples))
    multiplier = 1.0 + bonus + (ucb * 0.08 if samples < 8 else 0.0)
    return max(0.55, min(1.35, multiplier))
