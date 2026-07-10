#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Persist OSINT evidence bundles (ledger, STIX, synthesis)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from core.osint.config import get_osint_config
from core.osint.connectors.industry_mou import build_mou_requests_from_osint
from core.osint.connectors.sirius import build_sirius_requests_from_osint, push_sirius_template
from core.osint.evidence import OsintEvidenceCollector, utc_now_z
from core.osint.exporters.misp_exporter import export_osint_misp_event, push_misp_event
from core.osint.exporters.opencti_exporter import export_osint_opencti_bundle, push_opencti_bundle
from core.osint.exporters.remote_push import push_with_retry
from core.osint.exporters.umf_exporter import export_osint_umf_message
from core.osint.gdpr import (
    OsintRetentionPolicy,
    apply_gdpr_to_bundle_manifest,
    redact_pii_in_structure,
    write_gdpr_sidecar,
)
from core.osint.opsec import OsintOpsecJournal
from core.osint.providers import misp_endpoint, opencti_endpoint, sirius_endpoint
from core.osint.reports import generate_osint_reports
from core.osint.stix_exporter import export_osint_graph_stix


def write_osint_evidence_bundle(
    *,
    module_results: Sequence[Mapping[str, Any]],
    synthesis: Optional[Mapping[str, Any]] = None,
    output_dir: Path,
    run_id: str = "",
    legal_basis: str = "",
    target: str = "",
    tlp: str = "AMBER",
    actor: str = "workflow",
    workspace: str = "default",
    passive_only: bool = True,
    opsec_journal: Optional[OsintOpsecJournal] = None,
    push_remote: bool = True,
    retention_policy: Optional[OsintRetentionPolicy] = None,
    data_controller: str = "",
    recipient_org: str = "",
) -> Dict[str, str]:
    """Write ledger, evidence records, synthesis, and STIX bundle to ``output_dir``."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: Dict[str, str] = {}

    osint_cfg = get_osint_config()
    push_cfg = osint_cfg.push_settings()
    if push_remote and not push_cfg.get("enabled", True):
        push_remote = False
    push_attempts = int(push_cfg.get("max_attempts", 3) or 3)
    push_backoff = float(push_cfg.get("backoff_base", 1.5) or 1.5)

    general = osint_cfg.get_section("general")
    if not data_controller:
        data_controller = str(general.get("data_controller") or "")
    if not recipient_org:
        recipient_org = str(general.get("recipient_org") or "")
    if not tlp or tlp == "AMBER":
        tlp = str(general.get("default_tlp") or tlp or "AMBER")

    collector = OsintEvidenceCollector(
        run_id or f"osint_{utc_now_z()}",
        legal_basis=legal_basis,
        actor=actor,
    )
    for row in module_results or []:
        if isinstance(row, Mapping):
            collector.record_module_result(row)
    if synthesis:
        collector.record_synthesis(synthesis)

    paths.update(collector.persist(output_dir))

    if synthesis:
        synthesis_path = output_dir / "osint_synthesis.json"
        synthesis_path.write_text(json.dumps(dict(synthesis), indent=2), encoding="utf-8")
        paths["synthesis"] = str(synthesis_path)

    stix = export_osint_graph_stix(
        synthesis or {"nodes": [], "edges": [], "root_domain": target},
        case_id=target or run_id,
        tlp=tlp,
    )
    stix_path = output_dir / "osint_graph.stix.json"
    stix_path.write_text(json.dumps(stix, indent=2), encoding="utf-8")
    paths["stix"] = str(stix_path)

    synth = synthesis or {"nodes": [], "edges": [], "root_domain": target}
    misp_event = export_osint_misp_event(
        synth,
        module_results,
        case_id=target or run_id,
        tlp=tlp,
    )
    misp_path = output_dir / "osint_graph.misp.json"
    misp_path.write_text(json.dumps(misp_event, indent=2), encoding="utf-8")
    paths["misp"] = str(misp_path)

    opencti_bundle = export_osint_opencti_bundle(
        synth,
        module_results,
        case_id=target or run_id,
        tlp=tlp,
    )
    opencti_path = output_dir / "osint_graph.opencti.stix.json"
    opencti_path.write_text(json.dumps(opencti_bundle, indent=2), encoding="utf-8")
    paths["opencti"] = str(opencti_path)

    reports = generate_osint_reports(
        synth,
        module_results,
        case_id=target or run_id,
        legal_basis=legal_basis,
        tlp=tlp,
    )
    for level in ("strategic", "tactical", "operational"):
        report_path = output_dir / f"osint_report_{level}.json"
        report_path.write_text(json.dumps(reports[level], indent=2), encoding="utf-8")
        paths[f"report_{level}"] = str(report_path)
    md_path = output_dir / "osint_intel_report.md"
    md_path.write_text(str(reports.get("markdown") or ""), encoding="utf-8")
    paths["report_markdown"] = str(md_path)

    policy = retention_policy or OsintRetentionPolicy.from_osint_config()
    if data_controller:
        policy = OsintRetentionPolicy(
            pii_days=policy.pii_days,
            ioc_days=policy.ioc_days,
            audit_days=policy.audit_days,
            legal_basis_required=policy.legal_basis_required,
            pseudonymize_exports=policy.pseudonymize_exports,
            data_controller=data_controller,
            processing_purpose=policy.processing_purpose,
            lawful_basis_article=policy.lawful_basis_article,
        )
    gdpr_meta = apply_gdpr_to_bundle_manifest(
        {
            "generated_at": utc_now_z(),
            "case_id": target or run_id,
            "legal_basis": legal_basis,
        },
        policy,
        case_id=target or run_id,
        legal_basis=legal_basis,
    )
    paths["gdpr"] = write_gdpr_sidecar(output_dir, gdpr_meta)

    umf_message = export_osint_umf_message(
        synth,
        module_results,
        case_id=target or run_id,
        legal_basis=legal_basis,
        tlp=tlp,
        recipient_org=recipient_org,
        artifact_paths=paths,
    )
    if policy.pseudonymize_exports:
        umf_message = redact_pii_in_structure(umf_message, case_id=target or run_id, policy=policy)
    umf_path = output_dir / "osint_intel.umf.json"
    umf_path.write_text(json.dumps(umf_message, indent=2), encoding="utf-8")
    paths["umf"] = str(umf_path)

    sirius_requests = build_sirius_requests_from_osint(
        synth,
        module_results,
        case_id=target or run_id,
        legal_basis=legal_basis,
    )
    sirius_path = output_dir / "sirius_request_templates.json"
    sirius_path.write_text(json.dumps(sirius_requests, indent=2), encoding="utf-8")
    paths["sirius"] = str(sirius_path)

    mou_requests = build_mou_requests_from_osint(
        synth,
        module_results,
        case_id=target or run_id,
        legal_basis=legal_basis,
    )
    mou_path = output_dir / "industry_mou_templates.json"
    mou_path.write_text(json.dumps(mou_requests, indent=2), encoding="utf-8")
    paths["industry_mou"] = str(mou_path)

    journal = opsec_journal or OsintOpsecJournal(
        workspace=workspace,
        case_id=target or run_id,
        legal_basis=legal_basis,
        passive_only=passive_only,
    )
    for row in module_results or []:
        if isinstance(row, Mapping):
            journal.record(
                action="module_complete",
                module=str(row.get("path") or ""),
                target=str(row.get("target") or target),
                status=str(row.get("status") or "ok"),
            )
    paths["opsec_audit"] = journal.persist_session_log(output_dir)

    remote_status: Dict[str, Any] = {}
    if push_remote:
        misp_url, misp_key = misp_endpoint()
        if misp_url and misp_key:
            remote_status["misp"] = push_with_retry(
                lambda: push_misp_event(misp_event, url=misp_url, api_key=misp_key),
                max_attempts=push_attempts,
                backoff_base=push_backoff,
            )
        oti_url, oti_token = opencti_endpoint()
        if oti_url and oti_token:
            remote_status["opencti"] = push_with_retry(
                lambda: push_opencti_bundle(opencti_bundle, url=oti_url, token=oti_token),
                max_attempts=push_attempts,
                backoff_base=push_backoff,
            )
        sirius_url, sirius_token = sirius_endpoint()
        if sirius_url and sirius_token and sirius_requests:
            remote_status["sirius"] = push_with_retry(
                lambda: push_sirius_template(sirius_requests[0], url=sirius_url, token=sirius_token),
                max_attempts=min(2, push_attempts),
                backoff_base=push_backoff,
            )

    manifest = {
        "type": "osint_evidence_bundle",
        "generated_at": utc_now_z(),
        "run_id": run_id,
        "target": target,
        "legal_basis": legal_basis,
        "tlp": tlp,
        "artifact_paths": paths,
        "ledger_verified": collector.verify(),
        "module_count": len(collector.module_results),
        "opsec_summary": journal.summarize(),
        "remote_push": remote_status,
        "report_levels": ["strategic", "tactical", "operational"],
        "gdpr": gdpr_meta,
        "sirius_template_count": len(sirius_requests),
        "industry_mou_template_count": len(mou_requests),
        "osint_config": osint_cfg.config_file or "",
    }
    apply_gdpr_to_bundle_manifest(manifest, policy, case_id=target or run_id, legal_basis=legal_basis)
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    paths["manifest"] = str(manifest_path)
    return paths
