#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Context and suggestion types for the operator assistant."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class Suggestion:
    """A single actionable suggestion for the operator."""

    action: str
    reason: str = ""

    def display_line(self, index: int) -> str:
        action = str(self.action or "").strip()
        reason = str(self.reason or "").strip()
        if reason:
            return f"{index}. {action}  - {reason}"
        return f"{index}. {action}"


@dataclass
class AssistantContext:
    """Inputs used to build next-action suggestions."""

    event: str
    module: Any = None
    module_path: str = ""
    execution: Any = None
    session_id: str = ""
    session_type: str = ""
    sessions: List[Any] = field(default_factory=list)
    check_vulnerable: bool = False
    finding: Any = None
    evidence: Any = None
    knowledge_base: Optional[dict] = None
