#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Helpers for loading KittySploit JSON Schemas."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any, Dict, Iterable


SCHEMA_VERSION = "1.0"
DEFAULT_SCHEMA_SET = "v1"

ENTITY_SCHEMAS = {
    "common": "common.schema.json",
    "target": "target.schema.json",
    "evidence": "evidence.schema.json",
    "finding": "finding.schema.json",
    "job": "job.schema.json",
    "session": "session.schema.json",
    "report": "report.schema.json",
    "agent_action": "agent_action.schema.json",
    "agent_action_outcome": "agent_action_outcome.schema.json",
    "agent_stop_decision": "agent_stop_decision.schema.json",
    "agent_hypothesis": "agent_hypothesis.schema.json",
    "agent_observation": "agent_observation.schema.json",
    "agent_decision": "agent_decision.schema.json",
    "agent_state": "agent_state.schema.json",
    "agent_run": "agent_run.schema.json",
    "agent_benchmark_result": "agent_benchmark_result.schema.json",
    "agent_action_trace": "agent_action_trace.schema.json",
    "agent_tactical_rank": "agent_tactical_rank.schema.json",
    "agent_run_snapshot": "agent_run_snapshot.schema.json",
    "kittyforge_error": "kittyforge_error.schema.json",
    "generated_artifact": "generated_artifact.schema.json",
    "kittyforge_graph": "kittyforge_graph.schema.json",
    "signed_package": "signed_package.schema.json",
}


def _normalize_entity(entity: str) -> str:
    key = str(entity or "").strip().lower()
    if key not in ENTITY_SCHEMAS:
        allowed = ", ".join(sorted(ENTITY_SCHEMAS))
        raise KeyError(f"Unknown schema entity '{entity}'. Expected one of: {allowed}")
    return key


def list_schemas() -> Iterable[str]:
    """Return known schema entity names."""
    return tuple(sorted(ENTITY_SCHEMAS))


def schema_path(entity: str, schema_set: str = DEFAULT_SCHEMA_SET):
    """Return an importlib resource path-like object for a schema entity."""
    key = _normalize_entity(entity)
    return resources.files(__package__).joinpath("json", schema_set, ENTITY_SCHEMAS[key])


def load_schema(entity: str, schema_set: str = DEFAULT_SCHEMA_SET) -> Dict[str, Any]:
    """Load a schema entity as a dictionary."""
    path = schema_path(entity, schema_set)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
