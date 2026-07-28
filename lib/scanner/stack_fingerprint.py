#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lightweight HTTP stack fingerprint + module gating for bulk scanner runs.

Goal: skip CMS/SPA-specific modules (and their prefetch paths) when the target
shows no evidence of that stack — e.g. no WordPress → skip wordpress/wp-* modules.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from interfaces.command_system.builtin.agent.module_stack_gate import (
    cms_key_for_module_path,
    infer_stack_gate_for_path,
    resolve_module_stack_mismatch,
)

# Scanner modules with these tags require matching stack confidence.
TECH_TAG_MAP: Dict[str, frozenset[str]] = {
    "wordpress": frozenset(
        {"wordpress", "wp", "wp-plugin", "wp-theme", "wpscan"}
    ),
    "joomla": frozenset({"joomla"}),
    "drupal": frozenset({"drupal"}),
    "nextjs": frozenset({"nextjs", "next.js"}),
    "react": frozenset({"react"}),
}

# Confidence floor matching agent path-inferred scanner gates.
DEFAULT_CONFIDENCE_FLOOR = 0.3

# Cheap confirmation paths when homepage evidence is inconclusive.
CONFIRM_PATHS: Dict[str, Tuple[str, ...]] = {
    "wordpress": ("/wp-login.php", "/wp-json/"),
    "joomla": ("/administrator/", "/administrator/manifests/files/joomla.xml"),
    "drupal": ("/core/misc/drupal.js", "/user/login"),
}


def fingerprint_http_response(response: Any) -> Dict[str, Any]:
    """Build ``tech_hints`` / ``tech_confidence`` from a single HTTP response."""
    from lib.scanner.http.detectors import (
        classify_spa_stack,
        detect_drupal,
        detect_joomla,
        detect_php,
        detect_wordpress,
        is_nextjs,
        is_react,
    )

    hints: Set[str] = set()
    conf: Dict[str, float] = {}

    def _bump(tech: str, score: float) -> None:
        tech = str(tech).lower()
        hints.add(tech)
        conf[tech] = max(float(conf.get(tech, 0.0) or 0.0), float(score))

    if detect_wordpress(response):
        _bump("wordpress", 0.85)
        _bump("php", 0.55)
    if detect_joomla(response):
        _bump("joomla", 0.85)
        _bump("php", 0.55)
    if detect_drupal(response):
        _bump("drupal", 0.85)
        _bump("php", 0.55)

    php_ver = detect_php(response)
    if php_ver is not None or (hasattr(response, "headers") and "php" in str(
        (response.headers or {}).get("X-Powered-By", "")
    ).lower()):
        _bump("php", 0.6 if php_ver else 0.45)

    spa = classify_spa_stack(response)
    if spa == "nextjs" or is_nextjs(response):
        _bump("nextjs", 0.85)
        _bump("nodejs", 0.55)
        _bump("react", 0.55)
    elif spa.startswith("react") or is_react(response):
        _bump("react", 0.75)
        _bump("nodejs", 0.45)

    return {
        "tech_hints": sorted(hints),
        "tech_confidence": conf,
    }


def merge_fingerprint_kb(
    base: Optional[Mapping[str, Any]],
    extra: Mapping[str, Any],
) -> Dict[str, Any]:
    """Merge fingerprint dicts, keeping max confidence per tech."""
    out: Dict[str, Any] = {
        "tech_hints": [],
        "tech_confidence": {},
    }
    hints: Set[str] = set()
    conf: Dict[str, float] = {}
    for blob in (base or {}, extra or {}):
        for h in blob.get("tech_hints", []) or []:
            if str(h).strip():
                hints.add(str(h).lower())
        for tech, score in (blob.get("tech_confidence") or {}).items():
            try:
                val = float(score)
            except (TypeError, ValueError):
                continue
            key = str(tech).lower()
            conf[key] = max(float(conf.get(key, 0.0) or 0.0), val)
            if val >= DEFAULT_CONFIDENCE_FLOOR:
                hints.add(key)
    out["tech_hints"] = sorted(hints)
    out["tech_confidence"] = conf
    return out


def _module_tags(module: Mapping[str, Any]) -> Set[str]:
    return {str(t).lower() for t in (module.get("tags") or []) if str(t).strip()}


def tech_families_for_module(module: Mapping[str, Any]) -> Set[str]:
    """Return stack families this module is specialized for (path + tags)."""
    families: Set[str] = set()
    path = str(module.get("path") or "")
    cms = cms_key_for_module_path(path)
    if cms:
        families.add(cms)
    inferred = infer_stack_gate_for_path(path)
    req = (inferred.get("requires") or {}) if inferred else {}
    for key in ("confidence_min", "confidence_min_any"):
        block = req.get(key) or {}
        if isinstance(block, dict):
            families.update(str(t).lower() for t in block.keys())
    for hint in req.get("tech_hints_any") or []:
        low = str(hint).lower()
        if low in TECH_TAG_MAP:
            families.add(low)
        elif low in ("nodejs",):
            families.add("nextjs")
    tags = _module_tags(module)
    for tech, tech_tags in TECH_TAG_MAP.items():
        if tags & tech_tags:
            families.add(tech)
    return families


def families_present_in_modules(modules: Sequence[Mapping[str, Any]]) -> Set[str]:
    out: Set[str] = set()
    for module in modules:
        out |= tech_families_for_module(module)
    return out


def confidence_for(kb: Mapping[str, Any], tech: str) -> float:
    conf = kb.get("tech_confidence") or {}
    try:
        return float(conf.get(str(tech).lower(), 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def tag_stack_mismatch_reason(
    module: Mapping[str, Any],
    kb: Mapping[str, Any],
    *,
    floor: float = DEFAULT_CONFIDENCE_FLOOR,
) -> str:
    """
    Skip reason from module tags when path inference did not already gate it.

    Modules tagged wordpress/wp-plugin/... require wordpress confidence >= floor.
    """
    families = tech_families_for_module(module)
    if not families:
        return ""
    # Prefer CMS over SPA when both tagged (rare); check each family.
    for tech in sorted(families):
        if confidence_for(kb, tech) >= floor:
            return ""
    # nextjs modules also accept nodejs/react via path inference; tag-only
    # react/nextjs handled above. If any family met floor we returned "".
    needed = ", ".join(sorted(families))
    return f"requires stack evidence for: {needed}"


def filter_modules_by_stack(
    modules: Sequence[Dict[str, Any]],
    kb: Mapping[str, Any],
    *,
    floor: float = DEFAULT_CONFIDENCE_FLOOR,
) -> Tuple[List[Dict[str, Any]], List[Tuple[str, str]]]:
    """
    Return ``(kept_modules, skipped[(path, reason)])``.

    Uses agent path gates first, then tag-based CMS/SPA specialization.
    """
    kept: List[Dict[str, Any]] = []
    skipped: List[Tuple[str, str]] = []
    for module in modules:
        path = str(module.get("path") or "")
        reason = resolve_module_stack_mismatch(path, dict(kb), agent=None)
        if not reason:
            reason = tag_stack_mismatch_reason(module, kb, floor=floor)
        if reason:
            skipped.append((path, reason))
            continue
        kept.append(module)
    return kept, skipped


def summarize_skips(
    skipped: Sequence[Tuple[str, str]],
    modules: Optional[Sequence[Mapping[str, Any]]] = None,
    limit: int = 8,
) -> str:
    if not skipped:
        return ""
    by_path = {str(m.get("path") or ""): m for m in (modules or [])}
    by_family: Dict[str, int] = {}
    for path, _reason in skipped:
        module = by_path.get(path) or {"path": path, "tags": []}
        families = tech_families_for_module(module)
        cms = cms_key_for_module_path(path)
        if cms:
            key = cms
        elif families:
            key = sorted(families)[0]
        else:
            key = "other"
        by_family[key] = by_family.get(key, 0) + 1
    parts = [
        f"{name}={count}"
        for name, count in sorted(by_family.items(), key=lambda x: (-x[1], x[0]))
    ]
    detail = ", ".join(parts[:limit])
    if len(parts) > limit:
        detail += ", ..."
    return detail


def wordpress_confirm_signals(response: Any) -> bool:
    """True when a confirmation probe looks like WordPress."""
    if not response:
        return False
    code = int(getattr(response, "status_code", 0) or 0)
    text = (getattr(response, "text", None) or "")[:8000].lower()
    headers = getattr(response, "headers", None) or {}
    hdr = str(headers).lower()
    if code in (200, 401, 403) and any(
        m in text for m in ("wordpress", "wp-login", "wp-admin", '"name":"wordpress')
    ):
        return True
    if "x-pingback" in hdr and "xmlrpc.php" in hdr:
        return True
    if code == 200 and ("rest_route" in text or "namespaces" in text) and "wp" in text:
        return True
    # Typical wp-login form
    if code == 200 and "user_login" in text and "wp-submit" in text:
        return True
    return False


def joomla_confirm_signals(response: Any) -> bool:
    if not response:
        return False
    code = int(getattr(response, "status_code", 0) or 0)
    text = (getattr(response, "text", None) or "")[:8000].lower()
    if code in (200, 401, 403) and any(
        m in text for m in ("joomla", "com_login", "option=com_", "/media/system/js/")
    ):
        return True
    return False


def drupal_confirm_signals(response: Any) -> bool:
    if not response:
        return False
    code = int(getattr(response, "status_code", 0) or 0)
    text = (getattr(response, "text", None) or "")[:8000].lower()
    headers = getattr(response, "headers", None) or {}
    if "drupal" in str(headers.get("X-Generator", "")).lower():
        return True
    if code in (200, 401, 403) and any(
        m in text for m in ("drupal.settings", "drupal.js", "/sites/default/", "drupal")
    ):
        return True
    return False


CONFIRM_SIGNAL_FN = {
    "wordpress": wordpress_confirm_signals,
    "joomla": joomla_confirm_signals,
    "drupal": drupal_confirm_signals,
}


def apply_confirm_response(kb: Mapping[str, Any], tech: str, response: Any) -> Dict[str, Any]:
    """Merge confirmation probe evidence into the fingerprint kb."""
    fn = CONFIRM_SIGNAL_FN.get(tech)
    if not fn or not fn(response):
        return dict(kb) if isinstance(kb, dict) else {"tech_hints": [], "tech_confidence": {}}
    return merge_fingerprint_kb(
        kb,
        {
            "tech_hints": [tech],
            "tech_confidence": {tech: 0.8, "php": 0.5},
        },
    )


def needed_confirm_families(
    modules: Sequence[Mapping[str, Any]],
    kb: Mapping[str, Any],
    *,
    floor: float = DEFAULT_CONFIDENCE_FLOOR,
) -> List[str]:
    """CMS families present in module set but not yet confirmed on homepage."""
    needed: List[str] = []
    present = families_present_in_modules(modules)
    for tech in ("wordpress", "joomla", "drupal"):
        if tech in present and confidence_for(kb, tech) < floor:
            needed.append(tech)
    return needed
