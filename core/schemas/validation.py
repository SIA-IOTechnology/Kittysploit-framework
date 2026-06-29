#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""JSON Schema validation for KittySploit v1 mission objects."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from core.schemas import ENTITY_SCHEMAS, load_schema

try:
    from jsonschema import Draft202012Validator, FormatChecker, RefResolver

    _HAS_JSONSCHEMA = True
except ImportError:  # pragma: no cover
    Draft202012Validator = None  # type: ignore[assignment,misc]
    FormatChecker = None  # type: ignore[assignment,misc]
    RefResolver = None  # type: ignore[assignment,misc]
    _HAS_JSONSCHEMA = False

_SCHEMA_DIR = Path(__file__).resolve().parent / "json" / "v1"


class SchemaValidationError(Exception):
    """Raised when an instance does not satisfy its entity schema."""

    def __init__(
        self,
        entity: str,
        errors: Sequence[str],
        *,
        instance: Any = None,
    ) -> None:
        self.entity = str(entity)
        self.errors = [str(item) for item in errors if item]
        self.instance = instance
        message = f"{self.entity} schema validation failed"
        if self.errors:
            message = f"{message}: {'; '.join(self.errors)}"
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity": self.entity,
            "errors": list(self.errors),
            "message": str(self),
        }


def jsonschema_available() -> bool:
    return _HAS_JSONSCHEMA


@lru_cache(maxsize=None)
def _validator(entity: str) -> Any:
    if not _HAS_JSONSCHEMA:
        raise SchemaValidationError(
            entity,
            ["jsonschema package is required for schema validation"],
        )

    schemas: Dict[str, Dict[str, Any]] = {}
    store: Dict[str, Dict[str, Any]] = {}
    for name, filename in ENTITY_SCHEMAS.items():
        path = _SCHEMA_DIR / filename
        with path.open("r", encoding="utf-8") as handle:
            schema = json.load(handle)
        schemas[name] = schema
        store[schema["$id"]] = schema
        store[path.as_uri()] = schema

    schema = schemas[entity]
    resolver = RefResolver.from_schema(schema, store=store)
    return Draft202012Validator(
        schema,
        resolver=resolver,
        format_checker=FormatChecker(),
    )


def _format_errors(entity: str, instance: Any, exc: Exception) -> SchemaValidationError:
    if hasattr(exc, "context") and getattr(exc, "context", None):
        errors = [
            f"{error.json_path or '$'}: {error.message}"
            for error in exc.context  # type: ignore[attr-defined]
        ]
    else:
        errors = [str(exc)]
    return SchemaValidationError(entity, errors, instance=instance)


def validate_instance(entity: str, instance: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a single schema instance and return it unchanged on success."""
    if not isinstance(instance, dict):
        raise SchemaValidationError(entity, ["instance must be a JSON object"], instance=instance)
    validator = _validator(entity)
    try:
        validator.validate(instance)
    except Exception as exc:
        raise _format_errors(entity, instance, exc) from exc
    return instance


def validate_instances(entity: str, instances: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    validated: List[Dict[str, Any]] = []
    for index, instance in enumerate(instances):
        try:
            validated.append(validate_instance(entity, instance))
        except SchemaValidationError as exc:
            raise SchemaValidationError(
                entity,
                [f"item[{index}] {error}" for error in exc.errors],
                instance=instance,
            ) from exc
    return validated


def validate_evidence_records(records: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return validate_instances("evidence", records)


def validate_finding_record(record: Dict[str, Any]) -> Dict[str, Any]:
    return validate_instance("finding", record)
