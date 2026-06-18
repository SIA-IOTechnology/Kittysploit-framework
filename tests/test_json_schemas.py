#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")
from jsonschema import Draft202012Validator, FormatChecker, RefResolver

from core.schemas import load_schema, list_schemas


SCHEMA_DIR = Path(__file__).resolve().parents[1] / "core" / "schemas" / "json" / "v1"
SCHEMA_FILES = {
    "common": "common.schema.json",
    "target": "target.schema.json",
    "evidence": "evidence.schema.json",
    "finding": "finding.schema.json",
    "job": "job.schema.json",
    "session": "session.schema.json",
    "report": "report.schema.json",
}


def _load_all_schemas():
    schemas = {}
    for entity, filename in SCHEMA_FILES.items():
        with (SCHEMA_DIR / filename).open("r", encoding="utf-8") as handle:
            schemas[entity] = json.load(handle)
    return schemas


def _validator(entity):
    schemas = _load_all_schemas()
    store = {}
    for filename in SCHEMA_FILES.values():
        schema = schemas[filename.split(".")[0]]
        store[schema["$id"]] = schema
        store[(SCHEMA_DIR / filename).as_uri()] = schema

    schema = schemas[entity]
    resolver = RefResolver.from_schema(schema, store=store)
    return Draft202012Validator(
        schema,
        resolver=resolver,
        format_checker=FormatChecker(),
    )


def test_schema_loader_exposes_entities():
    assert set(list_schemas()) == set(SCHEMA_FILES)
    assert load_schema("Finding")["title"] == "KittySploit Finding"


def test_json_schemas_are_valid_draft_2020_12():
    for schema in _load_all_schemas().values():
        Draft202012Validator.check_schema(schema)


def test_entity_samples_validate():
    target = {
        "schema_version": "1.0",
        "id": "target-web-1",
        "type": "url",
        "raw": "https://example.test:443/login",
        "normalized": "https://example.test/login",
        "scheme": "https",
        "host": "example.test",
        "port": 443,
        "path": "/login",
        "protocol": "https",
        "service": {
            "name": "https",
            "port": 443,
            "protocol": "tcp",
            "state": "open"
        },
        "scope": {
            "in_scope": True,
            "reason": "authorized test fixture"
        },
        "metadata": {
            "source": "unit-test"
        }
    }

    evidence = {
        "schema_version": "1.0",
        "id": "ev-http-1",
        "kind": "http",
        "title": "Reflected marker observed",
        "summary": "Response reflected the harmless probe marker.",
        "collected_at": "2026-06-17T10:00:00Z",
        "target": target,
        "source": {
            "name": "scanner/http/xss_scanner",
            "type": "module"
        },
        "module": {
            "path": "scanner/http/xss_scanner",
            "name": "XSS Scanner",
            "type": "scanner"
        },
        "request": {
            "method": "GET",
            "url": "https://example.test/login?q=ks-marker",
            "headers": {
                "User-Agent": "KittySploit"
            }
        },
        "response": {
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html"
            },
            "body_text": "ks-marker",
            "elapsed_ms": 42
        },
        "confidence": 0.8,
        "metadata": {}
    }

    finding = {
        "schema_version": "1.0",
        "id": "finding-xss-1",
        "title": "Reflected XSS marker",
        "description": "A harmless marker was reflected without encoding.",
        "severity": "medium",
        "status": "affected",
        "affected_targets": [target],
        "evidence": [evidence],
        "module": "scanner/http/xss_scanner",
        "retest": {
            "required": True,
            "last_result": "pending"
        },
        "metadata": {
            "source": "unit-test"
        }
    }

    job = {
        "schema_version": "1.0",
        "id": 7,
        "name": "scanner/http/xss_scanner",
        "status": "completed",
        "target": target,
        "module": "scanner/http/xss_scanner",
        "pid": 1234,
        "started_at": "2026-06-17T09:59:00Z",
        "completed_at": "2026-06-17T10:00:00Z",
        "output": "completed",
        "result": {
            "success": True,
            "finding": "finding-xss-1",
            "evidence": ["ev-http-1"]
        }
    }

    session = {
        "schema_version": "1.0",
        "id": "session-1",
        "session_id": "session-1",
        "session_type": "shell",
        "target": target,
        "target_host": "example.test",
        "target_port": 443,
        "created_at": "2026-06-17T09:58:00Z",
        "last_seen": "2026-06-17T10:00:00Z",
        "is_active": True,
        "is_interactive": False,
        "data": {
            "commands_executed": 0
        }
    }

    report = {
        "schema_version": "1.0",
        "id": "report-1",
        "workspace": "default",
        "generated_at": "2026-06-17T10:01:00Z",
        "generated_by": "KittyReport Studio",
        "client_name": "Client",
        "template": "default",
        "formats": ["json", "md", "html"],
        "targets": [target],
        "findings": [finding],
        "evidence": [evidence],
        "jobs": [job],
        "sessions": [session],
        "summary": {
            "finding_count": 1,
            "host_count": 1,
            "target_count": 1,
            "job_count": 1,
            "session_count": 1,
            "status_counts": {
                "affected": 1
            },
            "severity_counts": {
                "medium": 1
            },
            "retest_pending": 1
        },
        "metadata": {
            "source": "unit-test"
        }
    }

    samples = {
        "target": target,
        "evidence": evidence,
        "finding": finding,
        "job": job,
        "session": session,
        "report": report,
    }
    for entity, sample in samples.items():
        _validator(entity).validate(sample)


def test_kittyreport_studio_bundle_shape_validates():
    bundle = {
        "schema_version": "1.0",
        "workspace": "default",
        "generated_at": "2026-06-17T09:15:42+00:00",
        "client_name": "Client",
        "template": "default",
        "findings": [
            {
                "id": "manual-eaaf3788",
                "title": "Test",
                "description": "",
                "severity": "medium",
                "status": "affected",
                "cve": None,
                "cvss_score": None,
                "affected_targets": [],
                "evidence": [],
                "remediation": None,
                "module": None,
                "retest": {
                    "required": True,
                    "last_tested_at": None,
                    "last_result": None,
                    "notes": None
                },
                "metadata": {
                    "source": "manual"
                }
            }
        ],
        "summary": {
            "finding_count": 1,
            "host_count": 0,
            "status_counts": {
                "affected": 1
            },
            "severity_counts": {
                "medium": 1
            },
            "retest_pending": 1
        },
        "metadata": {
            "host_count": 0,
            "source": "kittyreport-studio"
        }
    }

    _validator("report").validate(bundle)
