#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.workflows.definition import WorkflowDefinition, WorkflowStepDefinition, WorkflowVariableSpec

WORKFLOW_LIBRARY_DIR = Path(__file__).resolve().parent / "library"


def _parse_document(raw: Dict[str, Any], source: Optional[Path] = None) -> WorkflowDefinition:
    workflow_id = str(raw.get("id") or raw.get("workflow_id") or "").strip()
    if not workflow_id and source:
        workflow_id = source.stem
    if not workflow_id:
        raise ValueError("Workflow document must define 'id'")

    variables: Dict[str, WorkflowVariableSpec] = {}
    raw_vars = raw.get("variables") or {}
    if isinstance(raw_vars, dict):
        for name, spec in raw_vars.items():
            if isinstance(spec, dict):
                variables[name] = WorkflowVariableSpec(
                    name=name,
                    description=str(spec.get("description") or ""),
                    default=_stringify_default(spec.get("default")),
                    required=bool(spec.get("required", False)),
                )
            else:
                variables[name] = WorkflowVariableSpec(
                    name=name,
                    default=_stringify_default(spec),
                )

    steps: Dict[str, WorkflowStepDefinition] = {}
    raw_steps = raw.get("steps") or {}
    if not isinstance(raw_steps, dict):
        raise ValueError("'steps' must be a mapping of step name to step definition")

    for step_name, step_data in raw_steps.items():
        if not isinstance(step_data, dict):
            raise ValueError(f"Step '{step_name}' must be a mapping")
        step_type = str(step_data.get("type") or "module").strip().lower()
        steps[step_name] = WorkflowStepDefinition(
            name=step_name,
            module=step_data.get("module"),
            step_type=step_type,
            builtin_action=step_data.get("action") or step_data.get("builtin"),
            description=str(step_data.get("description") or ""),
            options=dict(step_data.get("options") or {}),
            input_mapping=dict(step_data.get("input_mapping") or {}),
            output_mapping=dict(step_data.get("output_mapping") or {}),
            on_success=step_data.get("on_success"),
            on_failure=step_data.get("on_failure"),
            when=step_data.get("when"),
        )

    start_step = str(raw.get("start_step") or "").strip()
    if not start_step:
        start_step = next(iter(steps), "")

    return WorkflowDefinition(
        workflow_id=workflow_id,
        name=str(raw.get("name") or workflow_id),
        description=str(raw.get("description") or ""),
        version=str(raw.get("version") or "1"),
        tags=list(raw.get("tags") or []),
        policy=dict(raw.get("policy") or {}),
        variables=variables,
        start_step=start_step,
        steps=steps,
        continue_on_failure=bool(raw.get("continue_on_failure", False)),
    )


def _stringify_default(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _load_yaml_or_json(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".json":
        data = json.loads(text)
    elif suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "PyYAML is required to load .yaml workflow files (pip install pyyaml)"
            ) from exc
        data = yaml.safe_load(text)
    else:
        raise ValueError(f"Unsupported workflow file type: {path.suffix}")
    if not isinstance(data, dict):
        raise ValueError(f"Workflow file must contain a mapping at root: {path}")
    return data


def load_workflow_file(path: Union[str, Path]) -> WorkflowDefinition:
    file_path = Path(path).expanduser().resolve()
    if not file_path.is_file():
        raise FileNotFoundError(f"Workflow file not found: {file_path}")
    return _parse_document(_load_yaml_or_json(file_path), source=file_path)


def load_workflow_definition(workflow_id: str) -> WorkflowDefinition:
    workflow_id = workflow_id.strip()
    if not workflow_id:
        raise ValueError("workflow_id is required")

    candidates = [
        WORKFLOW_LIBRARY_DIR / f"{workflow_id}.yaml",
        WORKFLOW_LIBRARY_DIR / f"{workflow_id}.yml",
        WORKFLOW_LIBRARY_DIR / f"{workflow_id}.json",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return load_workflow_file(candidate)
    raise FileNotFoundError(
        f"Workflow '{workflow_id}' not found in library ({WORKFLOW_LIBRARY_DIR})"
    )


def list_workflow_ids() -> List[str]:
    if not WORKFLOW_LIBRARY_DIR.is_dir():
        return []
    ids: List[str] = []
    for path in sorted(WORKFLOW_LIBRARY_DIR.iterdir()):
        if path.suffix.lower() in (".yaml", ".yml", ".json") and path.is_file():
            ids.append(path.stem)
    return ids
