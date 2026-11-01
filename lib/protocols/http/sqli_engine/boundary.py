#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Prefix/suffix (boundary) refinement after initial SQLi signals."""

from __future__ import annotations

from dataclasses import replace
from typing import Tuple

from .comparison import boolean_evidence
from .injection_context import InjectionContext
from .oracle import HttpParameterOracle, ProbeResponse
from .payloads import boolean_probes

_PAREN_CLOSES: Tuple[str, ...] = ("", ")", "))")
_COMMENT_SUFFIXES: Tuple[str, ...] = ("-- ", "#")


def refine_boundary(
    oracle: HttpParameterOracle,
    ctx: InjectionContext,
    baseline: ProbeResponse,
    *,
    max_trials: int = 6,
) -> InjectionContext:
    """
    Pick the best ``paren_close`` + SQL comment suffix using boolean true/false pairs.

    Typical case: ``1'`` vs ``1')`` when the value sits inside ``(... )`` in the query.
    """
    if ctx.numeric:
        return ctx

    best = ctx
    best_score = 0
    trials = 0

    for paren in _PAREN_CLOSES:
        for comment in _COMMENT_SUFFIXES:
            if trials >= max_trials:
                return best
            trials += 1
            trial = replace(ctx, paren_close=paren, comment=comment)
            (true_payload, _), (false_payload, _) = boolean_probes(trial)
            true_resp = oracle.send(true_payload)
            false_resp = oracle.send(false_payload)
            evidence = boolean_evidence(baseline, true_resp, false_resp)
            if not evidence:
                continue
            score = len(evidence) + (2 if paren else 0)
            if score > best_score:
                best_score = score
                best = trial

    return best
