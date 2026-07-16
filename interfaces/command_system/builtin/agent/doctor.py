#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Diagnostics for the autonomous agent command."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from typing import Any, Dict, List

from interfaces.command_system.builtin.agent.mission_profiles import list_mission_profiles
from interfaces.command_system.builtin.agent.run_store import AgentPathService


class AgentDoctor:
    def __init__(self, framework: Any) -> None:
        self.framework = framework

    def run(self) -> Dict[str, Dict[str, Any]]:
        paths = AgentPathService(self.framework)
        checks: Dict[str, Dict[str, Any]] = {}
        checks["langgraph"] = {
            "ok": importlib.util.find_spec("langgraph") is not None,
            "optional": True,
        }
        checks["requests"] = {
            "ok": importlib.util.find_spec("requests") is not None,
            "optional": False,
        }
        checks["aiohttp"] = {
            "ok": importlib.util.find_spec("aiohttp") is not None,
            "optional": True,
        }
        checks["jsonschema"] = {
            "ok": importlib.util.find_spec("jsonschema") is not None,
            "optional": True,
        }
        checks["scope_manager"] = {
            "ok": getattr(self.framework, "scope_manager", None) is not None,
            "enabled": bool(
                getattr(getattr(self.framework, "scope_manager", None), "enabled", False)
            ),
        }
        try:
            paths.ensure()
            probe = paths.root / ".write_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            writable = True
            error = ""
        except OSError as exc:
            writable = False
            error = str(exc)
        checks["storage"] = {
            "ok": writable,
            "path": str(paths.root),
            "error": error,
        }
        catalog = getattr(getattr(self.framework, "module_loader", None), "discover_modules", None)
        module_count = 0
        agent_meta_count = 0
        try:
            modules = catalog() if callable(catalog) else []
            module_count = len(modules)
            for row in modules:
                info = row.get("__info__", {}) if isinstance(row, dict) else {}
                agent = info.get("agent") if isinstance(info, dict) else None
                if isinstance(agent, dict) and agent.get("risk"):
                    agent_meta_count += 1
        except Exception:
            module_count = 0
        checks["module_catalog"] = {
            "ok": module_count > 0,
            "count": module_count,
            "agent_metadata_count": agent_meta_count,
        }
        checks["agent_home_env"] = {
            "ok": True,
            "value": os.environ.get("KITTYSPLOIT_AGENT_HOME", ""),
        }
        checks["llm_endpoint_loopback"] = self._check_llm_endpoint()
        checks["agent_schemas"] = self._check_agent_schemas()
        checks["agent_metadata_compliance"] = self._check_agent_metadata()
        checks["mission_profiles"] = {
            "ok": bool(list_mission_profiles()),
            "count": len(list_mission_profiles()),
        }
        checks["operator_archetypes"] = self._check_operator_archetypes()
        checks["evidence_gate"] = self._check_evidence_gate()
        checks["context_pack"] = self._check_context_pack()
        checks["adjudicate"] = self._check_adjudicate()
        return checks

    @staticmethod
    def _check_adjudicate() -> Dict[str, Any]:
        try:
            from interfaces.command_system.builtin.agent.adjudicate import (
                adjudicate,
                guard_exists_in_source,
            )

            panel = adjudicate([
                {"verdict": "REFUTED", "killing_guard": {"file": "a.c", "line": 1, "quote": "if (n >= cap)"}},
                {"verdict": "SURVIVED"},
                {"verdict": "SURVIVED"},
            ])
            guard_ok = guard_exists_in_source(
                {"file": "test.c", "line": 2, "quote": "if (n >= cap)"},
                "void f() { if (n >= cap) return; sink(n); }",
            )
            return {
                "ok": panel.get("verdict") == "SURVIVED" and guard_ok,
                "panel_verdict": panel.get("verdict"),
                "guard_cite_check": guard_ok,
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)[:200]}

    @staticmethod
    def _check_operator_archetypes() -> Dict[str, Any]:
        try:
            from interfaces.command_system.builtin.agent.operator_archetypes import (
                ARCHETYPE_PROFILES,
                list_operator_profiles,
                resolve_operator_for_phase,
            )

            profiles = list_operator_profiles()
            recon = resolve_operator_for_phase("scan")
            return {
                "ok": len(profiles) >= 6,
                "count": len(profiles),
                "sample": recon.key,
                "archetypes": list(ARCHETYPE_PROFILES.keys()),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)[:200]}

    @staticmethod
    def _check_evidence_gate() -> Dict[str, Any]:
        try:
            from interfaces.command_system.builtin.agent.evidence_gate import gate_live_finding

            blocked = gate_live_finding({"vulnerable": True, "severity": "high"})
            passed = gate_live_finding({
                "vulnerable": True,
                "evidence_records": [{"kind": "http", "summary": "status=200 body=uid=0"}],
            })
            return {
                "ok": not blocked["passed"] and passed["passed"],
                "blocks_empty": not blocked["passed"],
                "passes_with_tool_output": passed["passed"],
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)[:200]}

    @staticmethod
    def _check_context_pack() -> Dict[str, Any]:
        try:
            from interfaces.command_system.builtin.agent.context_pack import pack_knowledge_context

            packed = pack_knowledge_context(
                {"tech_hints": ["php", "apache"], "risk_signals": ["waf"]},
                objective="obtain-shell",
            )
            return {
                "ok": bool(packed.get("text")),
                "included": len(packed.get("included_sections", [])),
                "dropped": len(packed.get("dropped_sections", [])),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)[:200]}

    def run_json(self) -> Dict[str, Any]:
        checks = self.run()
        ok = all(bool(row.get("ok")) or bool(row.get("optional")) for row in checks.values())
        return {
            "ok": ok,
            "checks": checks,
        }

    @staticmethod
    def _check_llm_endpoint() -> Dict[str, Any]:
        endpoint = os.environ.get("KITTYSPLOIT_LLM_ENDPOINT", "http://127.0.0.1:11434/api/chat")
        try:
            from urllib.parse import urlsplit

            host = (urlsplit(endpoint).hostname or "").lower()
        except Exception:
            host = ""
        loopback = host in {"127.0.0.1", "::1", "localhost"}
        return {"ok": loopback, "endpoint": endpoint, "loopback": loopback}

    @staticmethod
    def _check_agent_schemas() -> Dict[str, Any]:
        import core.schemas as schemas_pkg

        from core.schemas import DEFAULT_SCHEMA_SET, ENTITY_SCHEMAS

        schema_dir = Path(schemas_pkg.__file__).resolve().parent / "json" / DEFAULT_SCHEMA_SET
        required = [
            "agent_action",
            "agent_decision",
            "agent_observation",
            "agent_run",
            "agent_state",
        ]
        missing = [
            ENTITY_SCHEMAS[name]
            for name in required
            if not (schema_dir / ENTITY_SCHEMAS[name]).is_file()
        ]
        return {"ok": not missing, "missing": missing, "path": str(schema_dir)}

    def _check_agent_metadata(self) -> Dict[str, Any]:
        from interfaces.command_system.builtin.agent.module_catalog import ModuleCatalogService

        audit = ModuleCatalogService(self.framework).audit_agent_metadata(limit_sample=5)
        compliant = int(audit.get("compliant", 0) or 0)
        total = int(audit.get("total_modules", 0) or 0)
        return {
            "ok": compliant > 0,
            "optional": compliant == 0,
            "total": total,
            "compliant": compliant,
            "partial": int(audit.get("partial", 0) or 0),
            "missing": int(audit.get("missing", 0) or 0),
            "coverage_ratio": audit.get("coverage_ratio", 0.0),
            "hint": "run `agent metadata --json` or `agent metadata families --suite metasploitable3-linux`",
        }
