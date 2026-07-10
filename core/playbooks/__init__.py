#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Structured attack playbooks derived from CTF / bug bounty case studies."""

from core.playbooks.loader import (
    PLAYBOOK_LIBRARY_DIR,
    list_playbook_ids,
    load_playbook_definition,
    load_playbook_file,
)
from core.playbooks.coverage import (
    assess_playbook_coverage,
    invalidate_playbook_planner_cache,
    playbook_readiness_bonus,
    refresh_playbook_planner_hints,
    summarize_playbook_coverage_for_report,
)
from core.playbooks.definition import AttackPlaybook, PlaybookChainStep, PlaybookPrerequisites

__all__ = [
    "AttackPlaybook",
    "PlaybookChainStep",
    "PlaybookPrerequisites",
    "PLAYBOOK_LIBRARY_DIR",
    "list_playbook_ids",
    "load_playbook_definition",
    "load_playbook_file",
    "assess_playbook_coverage",
    "summarize_playbook_coverage_for_report",
    "playbook_readiness_bonus",
    "refresh_playbook_planner_hints",
    "invalidate_playbook_planner_cache",
]
