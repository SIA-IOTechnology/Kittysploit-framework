#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Release gate and regression dashboard for agent benchmark phases."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from interfaces.command_system.builtin.agent.redaction import sanitize_nested

DEFAULT_ARTIFACT_DIR = Path("artifacts/benchmarks")
FIXTURE_BASELINE_PATH = Path("tests/fixtures/benchmarks/release_baseline.json")
PHASE_KEYS = ("phase3", "phase4", "phase5", "phase6")
MCR_REGRESSION_MARGIN = 0.02


@dataclass
class ReleaseGateReport:
    schema_version: str = "1.0"
    evaluated_at: str = ""
    passed: bool = False
    regressions: List[str] = field(default_factory=list)
    comparisons: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return sanitize_nested({
            "schema_version": self.schema_version,
            "evaluated_at": self.evaluated_at,
            "passed": self.passed,
            "regressions": list(self.regressions),
            "comparisons": self.comparisons,
            "notes": list(self.notes),
        })


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _extract_mcr(payload: Mapping[str, Any]) -> Optional[float]:
    """Normalize phase reports that use different MCR field names."""
    for key in ("mcr", "hierarchical_mcr", "micro_mcr"):
        if payload.get(key) is not None:
            try:
                return float(payload.get(key))
            except (TypeError, ValueError):
                pass
    micro = payload.get("micro_benchmark") if isinstance(payload.get("micro_benchmark"), dict) else {}
    for key in ("mcr", "hierarchical_mcr"):
        if micro.get(key) is not None:
            try:
                return float(micro.get(key))
            except (TypeError, ValueError):
                pass
    return None


def load_phase_artifact(phase: str, *, artifact_dir: Path = DEFAULT_ARTIFACT_DIR) -> Dict[str, Any]:
    key = str(phase).strip().lower()
    path = artifact_dir / f"{key}_validation_latest.json"
    payload = _load_json(path)
    if not payload:
        return {}
    safety = payload.get("safety") if isinstance(payload.get("safety"), dict) else {}
    mcr = _extract_mcr(payload)
    if mcr is None:
        return {}
    return {
        "mcr": float(mcr),
        "passed": bool(payload.get("passed")),
        "safety": dict(safety),
        "source": str(path),
    }


def load_current_artifacts(*, artifact_dir: Path = DEFAULT_ARTIFACT_DIR) -> Dict[str, Dict[str, Any]]:
    return {phase: load_phase_artifact(phase, artifact_dir=artifact_dir) for phase in PHASE_KEYS}


def load_baseline(*, path: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    target = path or FIXTURE_BASELINE_PATH
    payload = _load_json(target)
    phases = payload.get("phases") if isinstance(payload.get("phases"), dict) else payload
    out: Dict[str, Dict[str, Any]] = {}
    for phase in PHASE_KEYS:
        row = phases.get(phase) if isinstance(phases, dict) else None
        if isinstance(row, dict):
            out[phase] = {
                "mcr": float(row.get("mcr") or 0.0),
                "passed": bool(row.get("passed", True)),
                "safety": dict(row.get("safety") or {}),
            }
    return out


def _safety_regression(phase: str, baseline: Mapping[str, Any], current: Mapping[str, Any]) -> List[str]:
    issues: List[str] = []
    base_safety = baseline.get("safety") if isinstance(baseline.get("safety"), dict) else {}
    cur_safety = current.get("safety") if isinstance(current.get("safety"), dict) else {}
    for key in sorted(set(base_safety) | set(cur_safety)):
        try:
            base_val = int(base_safety.get(key) or 0)
            cur_val = int(cur_safety.get(key) or 0)
        except (TypeError, ValueError):
            continue
        if cur_val > base_val:
            issues.append(f"{phase} safety.{key} rose {base_val}→{cur_val}")
    return issues


def evaluate_release_gate(
    *,
    baseline: Optional[Mapping[str, Mapping[str, Any]]] = None,
    current: Optional[Mapping[str, Mapping[str, Any]]] = None,
    artifact_dir: Path = DEFAULT_ARTIFACT_DIR,
    baseline_path: Optional[Path] = None,
) -> ReleaseGateReport:
    """Fail if MCR or safety counters regress vs baseline."""
    base = dict(baseline or load_baseline(path=baseline_path))
    cur = dict(current or load_current_artifacts(artifact_dir=artifact_dir))
    report = ReleaseGateReport(evaluated_at=datetime.now(timezone.utc).isoformat())
    comparisons: Dict[str, Any] = {}

    for phase in PHASE_KEYS:
        base_row = dict(base.get(phase) or {})
        cur_row = dict(cur.get(phase) or {})
        if not base_row and not cur_row:
            continue
        if not cur_row:
            comparisons[phase] = {"baseline": base_row, "current": {}, "status": "missing"}
            report.notes.append(f"{phase}: missing current artifact — skipped")
            continue
        if not base_row:
            comparisons[phase] = {"baseline": {}, "current": cur_row, "status": "no_baseline"}
            report.notes.append(f"{phase}: no baseline — skipped")
            continue

        base_mcr = float(base_row.get("mcr") or 0.0)
        cur_mcr = float(cur_row.get("mcr") or 0.0)
        status = "ok"
        if cur_mcr + MCR_REGRESSION_MARGIN < base_mcr:
            status = "mcr_regression"
            report.regressions.append(
                f"{phase} MCR regressions: {cur_mcr:.1%} < baseline {base_mcr:.1%}"
            )
        for issue in _safety_regression(phase, base_row, cur_row):
            status = "safety_regression"
            report.regressions.append(issue)
        if base_row.get("passed") and not cur_row.get("passed"):
            status = "pass_flip"
            report.regressions.append(f"{phase} flipped passed→failed")
        comparisons[phase] = {
            "baseline_mcr": base_mcr,
            "current_mcr": cur_mcr,
            "status": status,
            "baseline": base_row,
            "current": cur_row,
        }

    report.comparisons = sanitize_nested(comparisons)
    report.passed = not report.regressions
    if report.passed:
        report.notes.append("No MCR/safety regressions vs baseline.")
    return report


def build_regression_dashboard(
    *,
    artifact_dir: Path = DEFAULT_ARTIFACT_DIR,
    baseline_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    gate = evaluate_release_gate(artifact_dir=artifact_dir, baseline_path=baseline_path)
    current = load_current_artifacts(artifact_dir=artifact_dir)
    dashboard = sanitize_nested({
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "release_gate_passed": gate.passed,
        "regressions": gate.regressions,
        "phases": {
            phase: {
                "mcr": (current.get(phase) or {}).get("mcr"),
                "passed": (current.get(phase) or {}).get("passed"),
                "safety": (current.get(phase) or {}).get("safety") or {},
                "comparison": (gate.comparisons or {}).get(phase) or {},
            }
            for phase in PHASE_KEYS
        },
        "notes": gate.notes,
    })
    target = output_path or (artifact_dir / "dashboard_latest.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dashboard, indent=2, sort_keys=True), encoding="utf-8")
    return dashboard


def write_release_gate_report(
    report: ReleaseGateReport,
    *,
    output_path: Optional[Path] = None,
) -> Path:
    target = output_path or (DEFAULT_ARTIFACT_DIR / "release_gate_latest.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return target
