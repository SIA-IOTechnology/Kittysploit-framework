#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Operator assistant: contextual next-action suggestions (non-chatbot)."""

from interfaces.command_system.builtin.assistant.context import AssistantContext, Suggestion
from interfaces.command_system.builtin.assistant.render import maybe_show_assistant

__all__ = [
    "AssistantContext",
    "Suggestion",
    "maybe_show_assistant",
]
