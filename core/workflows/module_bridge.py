#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Bridge declarative YAML workflow library into ``use workflow/<id>`` module paths."""

from __future__ import annotations

import os
from typing import Any, Dict, Optional, Type

from core.framework.option.option_bool import OptBool
from core.framework.option.option_string import OptString
from core.framework.workflow import Workflow
from core.workflows.definition import WorkflowDefinition, WorkflowVariableSpec
from core.workflows.loader import WORKFLOW_LIBRARY_DIR, load_workflow_definition, list_workflow_ids

LIBRARY_URI_PREFIX = "library://"
_CLASS_CACHE: Dict[str, Type[Workflow]] = {}


def library_workflow_uri(workflow_id: str) -> str:
    return f"{LIBRARY_URI_PREFIX}{workflow_id}"


def is_library_workflow_uri(uri: str) -> bool:
    return str(uri or "").startswith(LIBRARY_URI_PREFIX)


def workflow_id_from_uri(uri: str) -> str:
    return str(uri or "").removeprefix(LIBRARY_URI_PREFIX)


def normalize_workflow_slug(slug: str) -> str:
    return str(slug or "").strip().replace("_", "-")


def workflow_id_from_module_path(module_path: str) -> Optional[str]:
    path = str(module_path or "").strip().strip("/")
    if not path.startswith("workflow/"):
        return None
    slug = path.split("/", 1)[1].strip()
    if not slug or slug.startswith("_"):
        return None
    return normalize_workflow_slug(slug)


def discover_library_workflow_modules(modules_path: str) -> Dict[str, str]:
    """Map ``workflow/<id>`` module paths to library URIs (skip ids with a .py override)."""
    discovered: Dict[str, str] = {}
    for workflow_id in list_workflow_ids():
        module_path = f"workflow/{workflow_id}"
        py_path = os.path.join(modules_path, module_path.replace("/", os.sep) + ".py")
        if os.path.isfile(py_path):
            continue
        discovered[module_path] = library_workflow_uri(workflow_id)
    return discovered


def resolve_library_workflow_yaml_path(workflow_id: str):
    for suffix in (".yaml", ".yml", ".json"):
        candidate = WORKFLOW_LIBRARY_DIR / f"{workflow_id}{suffix}"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"Workflow '{workflow_id}' not found in library")


def library_workflow_options(definition: WorkflowDefinition) -> Dict[str, Any]:
    options: Dict[str, Any] = {
        "dry_run": {
            "default": "false",
            "required": False,
            "description": "Print execution plan without running modules",
            "advanced": False,
        }
    }
    for name, spec in definition.variables.items():
        options[name] = {
            "default": spec.default or "",
            "required": spec.required,
            "description": spec.description,
            "advanced": False,
        }
    return options


def library_workflow_sync_metadata(workflow_id: str) -> Dict[str, Any]:
    definition = load_workflow_definition(workflow_id)
    meta = library_workflow_search_metadata(workflow_id)
    meta["options"] = library_workflow_options(definition)
    return meta


def library_workflow_search_metadata(workflow_id: str) -> Dict[str, Any]:
    definition = load_workflow_definition(workflow_id)
    return {
        "name": definition.name,
        "description": definition.description,
        "author": "KittySploit Workflow Library",
        "tags": [t.lower() for t in (definition.tags or []) if t],
        "cve": "",
        "platform": "",
        "protocol": "",
        "reliability": "",
    }


class LibraryWorkflowBase(Workflow):
    """Execute a declarative library workflow through WorkflowEngine."""

    TYPE_MODULE = "workflow"
    _library_workflow_id: str = ""

    def run(self):
        """Steps are defined in YAML; execution happens in ``_exploit``."""
        return None

    def _collect_variables(self, definition: WorkflowDefinition) -> Dict[str, str]:
        variables: Dict[str, str] = {}
        for name in definition.variables:
            if not hasattr(self, name):
                continue
            value = getattr(self, name)
            if value is None:
                continue
            text = str(value).strip()
            if text:
                variables[name] = text
        return variables

    def _exploit(self):
        from core.workflows.engine import WorkflowEngine

        definition = load_workflow_definition(self._library_workflow_id)
        variables = self._collect_variables(definition)
        dry_run = bool(getattr(self, "dry_run", False))

        engine = WorkflowEngine(self.framework)
        result = engine.run(definition, variables, dry_run=dry_run)
        return result.success


def _option_for_variable(spec: WorkflowVariableSpec):
    default = spec.default if spec.default is not None else ""
    return OptString(default, spec.description, required=spec.required)


def build_library_workflow_class(definition: WorkflowDefinition) -> Type[Workflow]:
    workflow_id = definition.workflow_id
    cached = _CLASS_CACHE.get(workflow_id)
    if cached is not None:
        return cached

    attrs: Dict[str, Any] = {
        "__info__": {
            "name": definition.name,
            "description": definition.description,
            "author": "KittySploit Workflow Library",
            "tags": list(definition.tags or []),
        },
        "_library_workflow_id": workflow_id,
        "dry_run": OptBool(False, "Print execution plan without running modules", required=False),
    }
    for name, spec in definition.variables.items():
        attrs[name] = _option_for_variable(spec)

    class_name = f"LibraryWorkflow_{workflow_id.replace('-', '_')}"
    cls = type(class_name, (LibraryWorkflowBase,), attrs)
    _CLASS_CACHE[workflow_id] = cls
    return cls


def load_library_workflow_module(module_path: str, framework=None) -> Optional[Workflow]:
    workflow_id = workflow_id_from_module_path(module_path)
    if not workflow_id:
        return None

    definition = load_workflow_definition(workflow_id)
    cls = build_library_workflow_class(definition)
    instance = cls(framework=framework) if framework is not None else cls()
    if framework is not None:
        instance.framework = framework
    if not instance.name:
        instance.name = definition.name or module_path
    return instance
