#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Immutable image pins and reset attestations for reproducible lab benchmarks."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Tuple

from core.lab_orchestrator.manifest import LabGroundTruthManifest


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def image_reference(image: Mapping[str, Any]) -> str:
    """Stable reference string for Docker or Vagrant lab images."""
    if not isinstance(image, dict):
        return ""
    provider = str(image.get("provider") or "docker").lower()
    if provider == "vagrant":
        box = str(image.get("box") or "").strip()
        version = str(image.get("box_version") or "").strip()
        return f"vagrant:{box}@{version}" if version else f"vagrant:{box}"
    name = str(image.get("name") or image.get("repository") or "").strip()
    tag = str(image.get("tag") or "latest").strip()
    digest = str(image.get("digest") or "").strip()
    if digest:
        return f"{name}@{digest}"
    if name and tag:
        return f"{name}:{tag}"
    return name


def expected_image_digest(manifest: LabGroundTruthManifest) -> str:
    digest = str((manifest.image or {}).get("digest") or "").strip()
    return digest


def provisioning_info(manifest: LabGroundTruthManifest) -> Dict[str, Any]:
    raw = dict((manifest.image or {}).get("provisioning") or {})
    if not raw:
        raw = dict(getattr(manifest, "provisioning", None) or {})
    return {
        "version": str(raw.get("version") or manifest.version or "1.0"),
        "method": str(raw.get("method") or (manifest.image or {}).get("provider") or "docker"),
        "sbom_ref": raw.get("sbom_ref"),
    }


def manifest_fingerprint(manifest: LabGroundTruthManifest) -> str:
    """Hash of oracle-visible manifest fields (excludes credential values)."""
    services = [
        {
            "id": item.id,
            "protocol": item.protocol,
            "port": item.port,
            "host_port": item.host_port,
            "required": item.required,
            "description": item.description,
        }
        for item in manifest.services
    ]
    session = dict(manifest.session or {})
    for secret_key in ("password", "secret", "token"):
        session.pop(secret_key, None)
    payload = {
        "id": manifest.id,
        "version": manifest.version,
        "image": {
            "provider": (manifest.image or {}).get("provider"),
            "name": (manifest.image or {}).get("name"),
            "tag": (manifest.image or {}).get("tag"),
            "box": (manifest.image or {}).get("box"),
            "box_version": (manifest.image or {}).get("box_version"),
            "digest": (manifest.image or {}).get("digest"),
        },
        "network": dict(manifest.network or {}),
        "services": services,
        "expected_paths": list(manifest.expected_paths or []),
        "session": session,
        "terminal_privilege": manifest.terminal_privilege,
        "provisioning": provisioning_info(manifest),
    }
    return f"sha256:{_sha256_hex(payload)}"


def provisioning_fingerprint(manifest: LabGroundTruthManifest) -> str:
    payload = {
        "image_reference": image_reference(manifest.image or {}),
        "provisioning": provisioning_info(manifest),
    }
    return f"sha256:{_sha256_hex(payload)}"


def build_reset_attestation(
    *,
    lab_id: str,
    manifest: LabGroundTruthManifest,
    image_digest: str = "",
    readiness_passed: bool,
    event: str = "start",
    extra: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Create a signed attestation record after a successful lab start or reset."""
    manifest_digest = expected_image_digest(manifest)
    resolved_digest = str(image_digest or manifest_digest or "").strip()
    body: Dict[str, Any] = {
        "id": f"attest_{uuid.uuid4().hex[:12]}",
        "event": str(event or "start"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "lab_id": str(lab_id),
        "manifest_id": manifest.id,
        "manifest_version": manifest.version,
        "manifest_fingerprint": manifest_fingerprint(manifest),
        "image_reference": image_reference(manifest.image or {}),
        "image_digest": resolved_digest or None,
        "provisioning_version": provisioning_info(manifest)["version"],
        "provisioning_fingerprint": provisioning_fingerprint(manifest),
        "readiness_passed": bool(readiness_passed),
    }
    if extra:
        body.update(dict(extra))
    body["attestation_hash"] = f"sha256:{_sha256_hex({k: v for k, v in body.items() if k != 'attestation_hash'})}"
    return body


def verify_attestation_hash(attestation: Mapping[str, Any]) -> Tuple[bool, str]:
    if not isinstance(attestation, dict):
        return False, "Attestation payload missing"
    recorded = str(attestation.get("attestation_hash") or "").strip()
    if not recorded:
        return False, "Attestation hash missing"
    body = {k: v for k, v in attestation.items() if k != "attestation_hash"}
    expected = f"sha256:{_sha256_hex(body)}"
    if recorded != expected:
        return False, "Attestation hash mismatch (record may be tampered)"
    return True, "Attestation hash valid"


def verify_reset_attestation(
    attestation: Optional[Mapping[str, Any]],
    manifest: LabGroundTruthManifest,
    *,
    require_digest_pin: bool = False,
    require_readiness: bool = True,
) -> Tuple[bool, str]:
    """Validate that a reset attestation matches the current ground-truth manifest."""
    if not attestation or not isinstance(attestation, dict):
        return False, "No reset attestation recorded — run `lab start` or `lab reset` first"

    ok, detail = verify_attestation_hash(attestation)
    if not ok:
        return False, detail

    if str(attestation.get("manifest_id") or "") != manifest.id:
        return False, "Attestation manifest_id does not match current lab manifest"

    expected_fp = manifest_fingerprint(manifest)
    if str(attestation.get("manifest_fingerprint") or "") != expected_fp:
        return False, "Attestation manifest fingerprint stale — re-run `lab reset` after manifest changes"

    if require_readiness and not bool(attestation.get("readiness_passed")):
        return False, "Last lab reset did not pass readiness checks"

    pinned = expected_image_digest(manifest)
    resolved = str(attestation.get("image_digest") or "").strip()
    if require_digest_pin and not pinned:
        return False, (
            "Manifest image digest is not pinned — run `lab pin-digest <lab_id>` "
            "before benchmark promotion"
        )
    if pinned and resolved and pinned != resolved:
        return False, f"Attestation digest {resolved[:24]}... != manifest pin {pinned[:24]}..."
    if pinned and not resolved:
        return False, "Attestation missing resolved image digest"

    return True, "Reset attestation valid"


def apply_manifest_environment_options(
    options: Dict[str, Any],
    manifest: LabGroundTruthManifest,
) -> Dict[str, Any]:
    """Merge manifest image pins into docker/vagrant environment module options."""
    merged = dict(options or {})
    image = manifest.image or {}
    provider = str(image.get("provider") or "docker").lower()
    digest = expected_image_digest(manifest)

    if provider == "vagrant":
        if image.get("box"):
            merged.setdefault("vagrant_box", image.get("box"))
        return merged

    name = str(image.get("name") or "").strip()
    tag = str(image.get("tag") or "latest").strip()
    if name:
        merged.setdefault("image_name", f"{name}:{tag}" if tag else name)
    if digest:
        merged["expected_image_digest"] = digest
    return merged


def update_manifest_digest(manifest_path: str, digest: str) -> Dict[str, Any]:
    """Persist a resolved sha256 digest into a ground-truth manifest JSON file."""
    from pathlib import Path

    path = Path(manifest_path)
    with path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    image = dict(raw.get("image") or {})
    image["digest"] = str(digest or "").strip()
    raw["image"] = image
    with path.open("w", encoding="utf-8") as handle:
        json.dump(raw, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return raw
