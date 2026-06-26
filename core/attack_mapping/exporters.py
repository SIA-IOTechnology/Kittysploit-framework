#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from core.attack_mapping.models import AttackCatalog, AttackModuleMapping


def _uuid(prefix: str) -> str:
    return f"{prefix}--{uuid.uuid4()}"


def export_navigator_layer(
    catalog: AttackCatalog,
    *,
    name: str = "KittySploit Module Coverage",
    description: str = "",
) -> Dict[str, Any]:
    techniques: Dict[str, Dict[str, Any]] = {}
    for mapping in catalog.mappings:
        score_base = 2 if mapping.declared else 1
        for technique in mapping.all_techniques:
            entry = techniques.setdefault(
                technique,
                {
                    "techniqueID": technique,
                    "score": 0,
                    "comment": "",
                    "enabled": True,
                    "metadata": [],
                },
            )
            entry["score"] += score_base
            note = mapping.module_path
            if mapping.detections:
                note += " [detections documented]"
            entry["comment"] = (entry["comment"] + "; " + note).strip("; ")
            entry["metadata"].append(
                {
                    "module_path": mapping.module_path,
                    "declared": mapping.declared,
                    "detections": len(mapping.detections),
                    "artifacts": len(mapping.artifacts),
                }
            )

    return {
        "name": name,
        "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description
        or f"KittySploit offensive/defensive module coverage ({len(catalog.mappings)} modules)",
        "techniques": list(techniques.values()),
        "gradient": {
            "colors": ["#ffffff", "#ff6666", "#990000"],
            "minValue": 0,
            "maxValue": 10,
        },
        "legendItems": [
            {"label": "declared module mapping", "color": "#990000"},
            {"label": "inferred module mapping", "color": "#ff6666"},
        ],
    }


def export_stix_bundle(catalog: AttackCatalog) -> Dict[str, Any]:
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    objects: List[Dict[str, Any]] = []
    pattern_ids: Dict[str, str] = {}
    tool_ids: Dict[str, str] = {}

    identity_id = _uuid("identity")
    objects.append(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": generated,
            "modified": generated,
            "name": "KittySploit Framework",
            "identity_class": "organization",
        }
    )

    for technique, module_paths in catalog.technique_index.items():
        pattern_id = _uuid("attack-pattern")
        pattern_ids[technique] = pattern_id
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": pattern_id,
                "created": generated,
                "modified": generated,
                "name": technique,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique,
                        "url": f"https://attack.mitre.org/techniques/{technique}/",
                    }
                ],
            }
        )

    for mapping in catalog.mappings:
        tool_id = _uuid("tool")
        tool_ids[mapping.module_path] = tool_id
        objects.append(
            {
                "type": "tool",
                "spec_version": "2.1",
                "id": tool_id,
                "created": generated,
                "modified": generated,
                "name": mapping.module_name,
                "description": f"KittySploit module at {mapping.module_path}",
                "tool_types": ["penetration-testing"],
                "x_kittysploit_module_path": mapping.module_path,
                "x_kittysploit_module_type": mapping.module_type,
                "x_mitre_tactics": mapping.tactics,
                "x_mitre_prerequisites": mapping.prerequisites,
                "x_mitre_detections": mapping.detections,
                "x_mitre_artifacts": mapping.artifacts,
            }
        )
        for technique in mapping.all_techniques:
            pattern_id = pattern_ids.get(technique)
            if not pattern_id:
                continue
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _uuid("relationship"),
                    "created": generated,
                    "modified": generated,
                    "relationship_type": "uses",
                    "source_ref": tool_id,
                    "target_ref": pattern_id,
                    "description": "KittySploit module maps to MITRE ATT&CK technique",
                }
            )

    return {
        "type": "bundle",
        "id": _uuid("bundle"),
        "objects": objects,
    }


def export_taxii_collection_manifest(
    catalog: AttackCatalog,
    *,
    collection_id: str = "kittysploit-attack-mapping",
    title: str = "KittySploit ATT&CK Module Mapping",
) -> Dict[str, Any]:
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return {
        "type": "collection",
        "spec_version": "2.1",
        "id": collection_id,
        "title": title,
        "description": (
            "TAXII 2.1 collection manifest for KittySploit module ATT&CK mappings. "
            "Publish the companion STIX bundle to this collection endpoint."
        ),
        "created": generated,
        "modified": generated,
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
        "x_coverage": {
            "modules": len(catalog.mappings),
            "techniques": len(catalog.technique_index),
            "tactics": len(catalog.tactic_index),
            "declared_mappings": catalog.declared_count,
        },
    }


def export_heatmap_json(catalog: AttackCatalog) -> Dict[str, Any]:
    techniques: Dict[str, Dict[str, Any]] = {}
    for technique in sorted(set(catalog.technique_index) | set(catalog.offensive_techniques) | set(catalog.defensive_techniques)):
        offensive = catalog.offensive_techniques.get(technique, [])
        defensive = catalog.defensive_techniques.get(technique, [])
        techniques[technique] = {
            "offensive_count": len(offensive),
            "defensive_count": len(defensive),
            "offensive_modules": offensive,
            "defensive_modules": defensive,
            "total_modules": len(catalog.technique_index.get(technique, [])),
        }

    tactics: Dict[str, Dict[str, Any]] = {}
    for tactic, module_paths in catalog.tactic_index.items():
        related_techniques = sorted(
            {
                technique
                for technique, paths in catalog.technique_index.items()
                if any(path in module_paths for path in paths)
            }
        )
        tactics[tactic] = {
            "module_count": len(module_paths),
            "modules": module_paths,
            "techniques": related_techniques,
        }

    return {
        "summary": {
            "modules": len(catalog.mappings),
            "techniques": len(catalog.technique_index),
            "tactics": len(catalog.tactic_index),
            "declared_mappings": catalog.declared_count,
            "inferred_only_mappings": catalog.inferred_only_count,
        },
        "techniques": techniques,
        "tactics": tactics,
    }


def export_heatmap_markdown(catalog: AttackCatalog) -> str:
    heatmap = export_heatmap_json(catalog)
    lines = [
        "# KittySploit ATT&CK Coverage Heatmap",
        "",
        f"- Modules indexed: {heatmap['summary']['modules']}",
        f"- Techniques covered: {heatmap['summary']['techniques']}",
        f"- Declared mappings: {heatmap['summary']['declared_mappings']}",
        "",
        "## Technique coverage",
        "",
        "| Technique | Offensive | Defensive | Total |",
        "|---|---:|---:|---:|",
    ]
    for technique, row in sorted(heatmap["techniques"].items()):
        lines.append(
            f"| {technique} | {row['offensive_count']} | {row['defensive_count']} | {row['total_modules']} |"
        )
    lines.extend(["", "## Tactic coverage", ""])
    for tactic, row in sorted(heatmap["tactics"].items()):
        lines.append(
            f"- **{tactic}**: {row['module_count']} module(s), techniques: {', '.join(row['techniques']) or 'n/a'}"
        )
    return "\n".join(lines) + "\n"


def write_json_export(payload: Dict[str, Any], path: str) -> None:
    from pathlib import Path

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


def write_text_export(content: str, path: str) -> None:
    from pathlib import Path

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(content)
