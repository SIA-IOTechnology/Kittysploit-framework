#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Discover on-disk modules and build capability metadata without loading exploit code."""

import ast
import os
import re
from typing import Any, Dict, List, Optional

from interfaces.command_system.builtin.agent.agent_constants import (
    EXPANDED_SURFACE_MODULE_PREFIXES,
    NOTABLE_CATALOG_KEYWORDS,
    PURE_DETECTION_PATH_MARKERS,
    STRONG_VULN_SIGNAL_PHRASES,
)
from interfaces.command_system.builtin.agent.agent_module_meta import normalize_agent_block

RawModuleMap = Dict[str, str]


class ModuleCatalogService:
    """Side-effect-free views over `modules/` for planning and ranking."""

    def __init__(self, framework) -> None:
        self.framework = framework
        self._module_catalog_cache: Optional[RawModuleMap] = None
        self._agent_meta_cache: Dict[str, Any] = {}

    def _get_module_catalog(self) -> RawModuleMap:
        """Lazy in-memory cache of ``discover_modules()`` for this instance (one agent run)."""
        if self._module_catalog_cache is not None:
            return self._module_catalog_cache
        discovered = self.framework.module_loader.discover_modules()
        self._module_catalog_cache = discovered
        return discovered

    def invalidate_module_catalog_cache(self) -> None:
        """Drop cache (e.g. after module tree changes on disk)."""
        self._module_catalog_cache = None
        self._agent_meta_cache.clear()

    def extract_static_module_metadata(self, file_path: str) -> Dict[str, Any]:
        metadata = {
            "name": "",
            "description": "",
            "author": "",
            "tags": [],
            "modules": [],
            "severity": "",
            "agent": None,
        }
        if not file_path or not os.path.isfile(file_path):
            return metadata
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                source = handle.read()
            tree = ast.parse(source, filename=file_path)
        except Exception:
            return metadata

        info_node = None
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__info__":
                    info_node = node.value
                    break
            if info_node is not None:
                break

        if info_node is None:
            return metadata
        try:
            info = ast.literal_eval(info_node)
        except Exception:
            return metadata
        if not isinstance(info, dict):
            return metadata

        metadata["name"] = str(info.get("name", "") or "")
        metadata["description"] = str(info.get("description", "") or "")
        author = info.get("author", "")
        if isinstance(author, (list, tuple)):
            metadata["author"] = ", ".join([str(x) for x in author if str(x).strip()])
        else:
            metadata["author"] = str(author or "")
        tags = info.get("tags", []) or []
        if isinstance(tags, (list, tuple, set)):
            metadata["tags"] = [str(tag).lower() for tag in tags if str(tag).strip()]
        modules = info.get("modules", []) or []
        if isinstance(modules, (list, tuple, set)):
            metadata["modules"] = [str(path).strip() for path in modules if str(path).strip()]
        metadata["severity"] = str(info.get("severity", "") or "")
        metadata["agent"] = normalize_agent_block(info.get("agent")) if "agent" in info else None
        return metadata

    def get_agent_metadata(self, module_path: str) -> Any:
        """Normalized ``__info__['agent']`` for ``module_path``, or ``None``."""
        if not module_path:
            return None
        key = str(module_path).strip()
        if key in self._agent_meta_cache:
            return self._agent_meta_cache[key]
        try:
            discovered = self._get_module_catalog()
            file_path = discovered.get(key)
            if not file_path:
                self._agent_meta_cache[key] = None
                return None
            meta = self.extract_static_module_metadata(file_path)
            ag = meta.get("agent")
            self._agent_meta_cache[key] = ag
            return ag
        except Exception:
            self._agent_meta_cache[key] = None
            return None

    def discover_campaign_modules(self, expanded: bool = False) -> List[Dict[str, Any]]:
        modules = []
        try:
            discovered = self._get_module_catalog()
            for module_path, file_path in discovered.items():
                in_core = (
                    module_path.startswith("scanner/")
                    or module_path.startswith("auxiliary/scanner/")
                )
                in_expanded = bool(expanded) and any(
                    module_path.startswith(p) for p in EXPANDED_SURFACE_MODULE_PREFIXES
                )
                if not (in_core or in_expanded):
                    continue
                static_meta = self.extract_static_module_metadata(file_path)
                modules.append({
                    "path": module_path,
                    "file_path": file_path,
                    "name": static_meta.get("name") or module_path,
                    "description": static_meta.get("description", ""),
                    "author": static_meta.get("author", ""),
                    "tags": static_meta.get("tags", []),
                    "modules": static_meta.get("modules", []),
                    "severity": static_meta.get("severity", ""),
                    "agent": static_meta.get("agent"),
                })
        except Exception:
            return []
        return sorted(modules, key=lambda row: row["path"])

    def build_module_capability_catalog(self) -> Dict[str, Any]:
        catalog = {
            "total_modules": 0,
            "by_family": {},
            "notable_modules": [],
            "all_paths": [],
            "semantic_index": [],
        }
        try:
            discovered = self._get_module_catalog()
            catalog["total_modules"] = len(discovered)
            for module_path, file_path in discovered.items():
                family = str(module_path).split("/")[0] if "/" in str(module_path) else "other"
                static_meta = self.extract_static_module_metadata(file_path)
                catalog["by_family"][family] = int(catalog["by_family"].get(family, 0)) + 1
                catalog["all_paths"].append(module_path)
                semantic_text = " ".join([
                    str(module_path),
                    str(static_meta.get("name", "")),
                    str(static_meta.get("description", "")),
                    " ".join([str(tag) for tag in static_meta.get("tags", [])]),
                    str(static_meta.get("severity", "")),
                ])
                catalog["semantic_index"].append({
                    "path": module_path,
                    "family": family,
                    "tokens": self._semantic_tokens(semantic_text)[:80],
                })

                is_notable = False
                path_blob = " ".join([
                    str(module_path).lower(),
                    str(static_meta.get("name", "")).lower(),
                    str(static_meta.get("description", "")).lower(),
                    " ".join([str(tag).lower() for tag in static_meta.get("tags", [])]),
                ])
                if module_path.startswith("exploits/"):
                    is_notable = True
                if any(token in path_blob for token in NOTABLE_CATALOG_KEYWORDS):
                    is_notable = True

                if is_notable:
                    catalog["notable_modules"].append({
                        "path": module_path,
                        "family": family,
                        "severity": static_meta.get("severity", "") or "unknown",
                        "tags": static_meta.get("tags", []),
                        "description": static_meta.get("description", ""),
                        "module_link": (static_meta.get("modules", []) or [None])[0],
                    })
            catalog["all_paths"] = sorted(list(set(catalog["all_paths"])))
            catalog["semantic_index"] = sorted(
                catalog["semantic_index"],
                key=lambda row: row.get("path", ""),
            )[:1200]
            catalog["notable_modules"] = sorted(
                catalog["notable_modules"],
                key=lambda row: (
                    0 if row.get("module_link") else 1,
                    0 if row.get("severity") in ("critical", "high") else 1,
                    row.get("path", ""),
                ),
            )[:300]
        except Exception:
            pass
        return catalog

    def _semantic_tokens(self, text: str) -> List[str]:
        stop = {
            "the", "and", "for", "with", "from", "this", "that", "module", "scanner",
            "detect", "detected", "target", "http", "https", "auxiliary", "exploit",
            "exploits", "vulnerability", "vulnerabilities", "check", "checks",
        }
        raw = re.findall(r"[a-zA-Z0-9_./-]{3,}", str(text or "").lower().replace("-", "_"))
        out: List[str] = []
        seen = set()
        for token in raw:
            for part in re.split(r"[/._]", token):
                if len(part) < 3 or part in stop or part.isdigit() or part in seen:
                    continue
                seen.add(part)
                out.append(part)
        return out

    def normalize_exploit_module_path(self, value: Any) -> str:
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned.startswith(("exploit/", "exploits/")):
                return cleaned
            return ""
        if isinstance(value, (list, tuple)):
            for item in value:
                cleaned = self.normalize_exploit_module_path(item)
                if cleaned:
                    return cleaned
        return ""

    def normalize_linked_module_paths(self, value: Any) -> List[str]:
        normalized = []
        seen = set()
        raw_items = []
        if isinstance(value, str):
            raw_items = [value]
        elif isinstance(value, (list, tuple, set)):
            raw_items = list(value)
        for item in raw_items:
            if not isinstance(item, str):
                continue
            cleaned = item.strip()
            if not cleaned:
                continue
            if not cleaned.startswith(("scanner/", "auxiliary/scanner/", "exploit/", "exploits/")):
                continue
            if cleaned in seen:
                continue
            seen.add(cleaned)
            normalized.append(cleaned)
        return normalized

    def is_pure_technology_detection_module(self, path: str, message: str = "") -> bool:
        path_low = str(path or "").lower()
        msg_low = str(message or "").lower()
        if not any(token in path_low for token in PURE_DETECTION_PATH_MARKERS):
            return False
        return not any(token in msg_low for token in STRONG_VULN_SIGNAL_PHRASES)
