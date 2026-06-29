#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class WorkflowVariableSpec:
    name: str
    description: str = ""
    default: Optional[str] = None
    required: bool = False


@dataclass
class WorkflowStepDefinition:
    name: str
    module: Optional[str] = None
    step_type: str = "module"
    builtin_action: Optional[str] = None
    description: str = ""
    options: Dict[str, Any] = field(default_factory=dict)
    input_mapping: Dict[str, str] = field(default_factory=dict)
    output_mapping: Dict[str, str] = field(default_factory=dict)
    on_success: Optional[str] = None
    on_failure: Optional[str] = None
    when: Optional[str] = None


@dataclass
class WorkflowDefinition:
    workflow_id: str
    name: str
    description: str = ""
    version: str = "1"
    tags: List[str] = field(default_factory=list)
    policy: Dict[str, Any] = field(default_factory=dict)
    variables: Dict[str, WorkflowVariableSpec] = field(default_factory=dict)
    start_step: str = ""
    steps: Dict[str, WorkflowStepDefinition] = field(default_factory=dict)
    continue_on_failure: bool = False

    @property
    def quick_win(self) -> bool:
        return "quick-win" in self.tags
