#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Render assistant suggestions when the feature flag is enabled."""

from __future__ import annotations

from typing import Any, Optional

from interfaces.command_system.builtin.assistant.context import AssistantContext
from interfaces.command_system.builtin.assistant.engine import AssistantEngine


def maybe_show_assistant(framework: Any, context: Optional[AssistantContext]) -> None:
    """No-op unless assistant is enabled and suggestions are non-empty."""
    if framework is None or context is None:
        return
    if not getattr(framework, "assistant_enabled", False):
        return

    try:
        from core.output_handler import is_thread_output_quiet, print_assistant_panel
    except Exception:
        return

    if is_thread_output_quiet():
        return

    # Prefer an existing agent KB on the framework when present
    if context.knowledge_base is None:
        for attr in ("agent_knowledge_base", "knowledge_base", "attack_kb"):
            kb = getattr(framework, attr, None)
            if isinstance(kb, dict) and kb:
                context.knowledge_base = kb
                break

    try:
        suggestions = AssistantEngine.suggest(context)
    except Exception:
        return

    if not suggestions:
        return

    lines = [s.display_line(i) for i, s in enumerate(suggestions, start=1)]
    print_assistant_panel("Assistant - next actions", lines)
