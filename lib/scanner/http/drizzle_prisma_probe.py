#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Drizzle ORM and Prisma schema/migration artifacts."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Tuple

_PRISMA_PATHS = (
    "/schema.prisma",
    "/prisma/schema.prisma",
    "/src/prisma/schema.prisma",
    "/db/schema.prisma",
    "/app/prisma/schema.prisma",
    "/prisma/migrations/migration_lock.toml",
    "/prisma/migrations/20240101000000_init/migration.sql",
)

_DRIZZLE_PATHS = (
    "/drizzle.config.ts",
    "/drizzle.config.js",
    "/drizzle/meta/_journal.json",
    "/drizzle/meta/0000_snapshot.json",
    "/drizzle/0000_initial.sql",
    "/src/db/schema.ts",
    "/db/schema.ts",
)

_PRISMA_MARKERS = ("generator", "datasource", "model ")
_DRIZZLE_MARKERS = ("drizzle", "schema", "pgTable", "sqliteTable", "mysqlTable")
_MIGRATION_MARKERS = ("CREATE TABLE", "ALTER TABLE", "INSERT INTO")


def _scan_path(path: str, text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    sample = text or ""
    if not sample.strip():
        return findings
    lowered = sample.lower()
    if any(p in path for p in ("schema.prisma", "prisma/")):
        if all(m in lowered for m in ("model", "datasource")) or "provider =" in lowered:
            models = re.findall(r"(?m)^\s*model\s+(\w+)", sample)
            findings.append(
                {
                    "orm": "prisma",
                    "path": path,
                    "kind": "schema_exposed",
                    "models": models[:30],
                    "model_count": len(models),
                    "severity": "high" if "url" in lowered and "env(" in lowered else "medium",
                }
            )
    if "migration" in path and any(m in sample.upper() for m in _MIGRATION_MARKERS):
        findings.append(
            {
                "orm": "prisma",
                "path": path,
                "kind": "migration_sql_exposed",
                "severity": "high",
                "preview": sample[:400],
            }
        )
    if any(p in path for p in ("drizzle", "schema.ts")):
        if any(m in sample for m in _DRIZZLE_MARKERS):
            tables = re.findall(r"(?:pgTable|sqliteTable|mysqlTable)\s*\(\s*['\"](\w+)['\"]", sample)
            findings.append(
                {
                    "orm": "drizzle",
                    "path": path,
                    "kind": "schema_exposed",
                    "tables": tables[:30],
                    "table_count": len(tables),
                    "severity": "high",
                }
            )
    if path.endswith("_journal.json") and "dialect" in lowered:
        findings.append(
            {
                "orm": "drizzle",
                "path": path,
                "kind": "migration_journal",
                "severity": "medium",
                "preview": sample[:300],
            }
        )
    return findings


def collect_orm_artifact_bodies(http_request: Callable[..., Any]) -> List[Tuple[str, str]]:
    bodies: List[Tuple[str, str]] = []
    for path in _PRISMA_PATHS + _DRIZZLE_PATHS:
        response = http_request(method="GET", path=path, allow_redirects=False)
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            continue
        text = str(getattr(response, "text", "") or "")
        if text.strip():
            bodies.append((path, text))
    return bodies


def scan_drizzle_prisma_exposure(http_request: Callable[..., Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path, text in collect_orm_artifact_bodies(http_request):
        findings.extend(_scan_path(path, text))
    return findings


__all__ = ["scan_drizzle_prisma_exposure", "collect_orm_artifact_bodies"]
