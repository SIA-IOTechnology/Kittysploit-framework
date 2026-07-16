#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Ground-truth manifests for agent lab scenarios."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.utils.paths import framework_root


@dataclass
class LabServiceManifest:
    id: str
    protocol: str
    port: int
    host_port: int
    description: str = ""
    banner_contains: Optional[str] = None
    required: bool = True


@dataclass
class LabGroundTruthManifest:
    id: str
    version: str
    image: Dict[str, Any]
    network: Dict[str, Any]
    credentials: Dict[str, Any]
    services: List[LabServiceManifest] = field(default_factory=list)
    expected_paths: List[Dict[str, Any]] = field(default_factory=list)
    session: Dict[str, Any] = field(default_factory=dict)
    terminal_privilege: str = "user"
    tags: List[str] = field(default_factory=list)
    source_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["services"] = [asdict(item) for item in self.services]
        return payload

    def required_services(self) -> List[LabServiceManifest]:
        return [item for item in self.services if item.required]

    def service_coverage_ratio(self, discovered_ids: List[str]) -> float:
        required = self.required_services()
        if not required:
            return 1.0
        found = sum(1 for item in required if item.id in set(discovered_ids))
        return found / len(required)


def default_manifests_dir() -> Path:
    root = framework_root()
    if root is None:
        return Path("labs/manifests")
    return root / "labs" / "manifests"


def load_ground_truth_manifest(path: str | Path) -> LabGroundTruthManifest:
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)

    services = [
        LabServiceManifest(
            id=str(item.get("id") or ""),
            protocol=str(item.get("protocol") or "tcp"),
            port=int(item.get("port") or 0),
            host_port=int(item.get("host_port") or item.get("port") or 0),
            description=str(item.get("description") or ""),
            banner_contains=item.get("banner_contains"),
            required=bool(item.get("required", True)),
        )
        for item in raw.get("services") or []
    ]

    manifest_id = str(raw.get("id") or file_path.stem)
    return LabGroundTruthManifest(
        id=manifest_id,
        version=str(raw.get("version") or "1.0"),
        image=dict(raw.get("image") or {}),
        network=dict(raw.get("network") or {}),
        credentials=dict(raw.get("credentials") or {}),
        services=services,
        expected_paths=[dict(item) for item in raw.get("expected_paths") or []],
        session=dict(raw.get("session") or {}),
        terminal_privilege=str(raw.get("terminal_privilege") or "user"),
        tags=[str(tag) for tag in raw.get("tags") or []],
        source_path=str(file_path),
    )


def find_ground_truth_manifest(manifest_id: str, manifests_dir: Path | None = None) -> LabGroundTruthManifest:
    root = manifests_dir or default_manifests_dir()
    candidate = root / f"{manifest_id}.json"
    if candidate.is_file():
        return load_ground_truth_manifest(candidate)
    raise FileNotFoundError(f"Ground truth manifest not found: {manifest_id}")
