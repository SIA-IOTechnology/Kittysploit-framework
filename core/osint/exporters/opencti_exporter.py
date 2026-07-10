#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Export OSINT intel for OpenCTI (STIX bundle + optional GraphQL push)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Mapping, Optional, Sequence

from core.osint.mitre_mapping import infer_mitre_techniques, stix_external_references
from core.osint.stix_exporter import export_osint_graph_stix


def export_osint_opencti_bundle(
    synthesis: Mapping[str, Any],
    module_results: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    case_id: str = "",
    tlp: str = "AMBER",
    name: str = "KittySploit OSINT Import",
) -> Dict[str, Any]:
    """
    OpenCTI ingests STIX 2.1 bundles. Enrich with OpenCTI custom labels/metadata.
    """
    bundle = export_osint_graph_stix(
        synthesis,
        case_id=case_id,
        tlp=tlp,
        name=name,
    )
    techniques = infer_mitre_techniques(synthesis, module_results or [])
    ext_refs = stix_external_references(techniques)
    for obj in bundle.get("objects") or []:
        if not isinstance(obj, dict):
            continue
        labels = list(obj.get("labels") or [])
        if f"tlp:{tlp.lower()}" not in labels:
            labels.append(f"tlp:{tlp.lower()}")
        labels.append("kittysploit-osint")
        for row in techniques:
            tid = str(row.get("id") or "")
            if tid:
                labels.append(f"mitre-{tid}")
        obj["labels"] = labels
        if case_id and obj.get("type") in ("identity", "domain-name", "email-addr", "user-account"):
            obj["x_opencti_case_id"] = case_id
        if obj.get("type") == "report" and ext_refs:
            obj["external_references"] = ext_refs

    bundle["x_opencti_import"] = {
        "format": "stix2.1",
        "module_result_count": len(list(module_results or [])),
        "node_count": synthesis.get("node_count"),
        "edge_count": synthesis.get("edge_count"),
        "mitre_techniques": techniques,
    }
    return bundle


def push_opencti_bundle(
    bundle: Mapping[str, Any],
    *,
    url: str,
    token: str,
    timeout: int = 60,
) -> Dict[str, Any]:
    """Upload STIX bundle via OpenCTI GraphQL ``stixImport`` mutation."""
    base = str(url or "").strip().rstrip("/")
    auth = str(token or "").strip()
    if not base or not auth:
        return {"ok": False, "error": "OpenCTI URL and token required"}

    mutation = """
    mutation StixImport($file: Upload!, $connectorId: String) {
      stixImport(file: $file, connectorId: $connectorId) {
        id
        name
      }
    }
    """
    _ = mutation  # reserved for multipart upload integrations
    import_payload = {
        "query": """
        mutation Import($fileName: String!, $fileMarkings: [String], $bundle: String!) {
          stixBundleImport(fileName: $fileName, fileMarkings: $fileMarkings, bundle: $bundle) {
            id
            status
          }
        }
        """,
        "variables": {
            "fileName": "kittysploit-osint.json",
            "fileMarkings": [],
            "bundle": json.dumps(dict(bundle)),
        },
    }
    req = urllib.request.Request(
        f"{base}/graphql",
        data=json.dumps(import_payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {auth}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
            errors = body.get("errors")
            if errors:
                return {"ok": False, "error": str(errors)[:500]}
            return {"ok": True, "data": body.get("data")}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": exc.code, "error": exc.read().decode("utf-8", errors="replace")[:500]}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
