#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Load prestage modules from modules/prestage/ and materialize embeddable code."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from core.module_loader import ModuleLoader


_PLATFORM_ALIASES = {
    "linux": {"linux", "unix", "multi", "all"},
    "unix": {"linux", "unix", "multi", "all"},
    "darwin": {"darwin", "unix", "multi", "all"},
    "windows": {"windows", "multi", "all"},
    "multi": {"linux", "unix", "darwin", "windows", "multi", "all"},
    "all": {"linux", "unix", "darwin", "windows", "multi", "all"},
}


def _platform_compatible(requested: str, supported_tokens: Set[str]) -> bool:
    req = (requested or "all").strip().lower()
    tokens = {str(t).strip().lower() for t in supported_tokens if str(t).strip()}
    if not tokens:
        tokens = {"all"}
    if "all" in tokens or "multi" in tokens:
        return True
    allowed = _PLATFORM_ALIASES.get(req, {req, "multi", "all"})
    return bool(tokens & allowed)


@dataclass
class PrestStageModuleRef:
    prestage_id: str
    module_path: str
    description: str
    platforms: Set[str] = field(default_factory=lambda: {"all"})
    languages: Set[str] = field(default_factory=lambda: {"python"})
    dependencies: List[str] = field(default_factory=list)

    def matches_platform(self, platform: str) -> bool:
        return _platform_compatible(platform, self.platforms)


@dataclass
class MaterializedPrestage:
    prestage_id: str
    module_path: str
    description: str
    code: str
    platforms: Set[str] = field(default_factory=lambda: {"all"})
    dependencies: List[str] = field(default_factory=list)


_loader = ModuleLoader()
_catalog: Dict[str, PrestStageModuleRef] = {}
_catalog_by_id: Dict[str, Dict[str, PrestStageModuleRef]] = {}
_loaded = False


def _modules_root() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "modules", "prestage")


def _normalize_key(value: str) -> str:
    return str(value or "").strip().replace("\\", "/")


def _resolve_module_path(key: str) -> Optional[str]:
    key = _normalize_key(key)
    if not key:
        return None
    if key in _catalog:
        return _catalog[key].module_path
    if not key.startswith("prestage/"):
        alt = f"prestage/{key.replace('.', '/')}"
        if alt in _catalog:
            return _catalog[alt].module_path
    return None


def _register_ref(ref: PrestStageModuleRef) -> None:
    _catalog[ref.module_path] = ref
    short = ref.module_path.split("/")[-1]
    if short and short not in _catalog:
        _catalog[short] = ref

    bucket = _catalog_by_id.setdefault(ref.prestage_id, {})
    for lang in ref.languages:
        bucket[str(lang).strip().lower()] = ref
    if ref.prestage_id not in _catalog:
        _catalog[ref.prestage_id] = ref


def _pick_ref_for_language(ref: PrestStageModuleRef, language: str) -> PrestStageModuleRef:
    lang = str(language or "").strip().lower()
    if not lang:
        return ref
    by_lang = _catalog_by_id.get(ref.prestage_id) or {}
    if lang in by_lang:
        return by_lang[lang]
    if lang in ref.languages:
        return ref
    raise ValueError(
        f"Prestage '{ref.prestage_id}' does not support language '{lang}' "
        f"(supported: {', '.join(sorted(by_lang.keys() or ref.languages))})"
    )


def discover_prestage_modules(*, force: bool = False) -> Dict[str, PrestStageModuleRef]:
    global _loaded
    if _loaded and not force:
        return dict(_catalog)

    _catalog.clear()
    _catalog_by_id.clear()
    root = _modules_root()
    if os.path.isdir(root):
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                if not filename.endswith(".py") or filename.startswith("__"):
                    continue
                abs_path = os.path.join(dirpath, filename)
                rel = os.path.relpath(abs_path, os.path.join(root, "..")).replace(os.sep, "/")
                module_path = os.path.splitext(rel)[0]
                instance = _loader.load_module(module_path, load_only=True, silent=True, fast=True)
                if instance is None or not hasattr(instance, "generate"):
                    continue
                prestage_id = ""
                if hasattr(instance, "prestage_id"):
                    try:
                        prestage_id = str(instance.prestage_id()).strip()
                    except Exception:
                        prestage_id = ""
                if not prestage_id:
                    prestage_id = module_path.split("/")[-1]

                info = getattr(instance.__class__, "__info__", {}) or {}
                platforms = set()
                if hasattr(instance, "platform_tokens"):
                    try:
                        platforms = set(instance.platform_tokens())
                    except Exception:
                        platforms = {"all"}
                if not platforms:
                    platforms = {"all"}

                languages = set()
                if hasattr(instance, "supported_languages"):
                    try:
                        languages = set(instance.supported_languages())
                    except Exception:
                        languages = {"python"}
                if not languages:
                    languages = {"python"}

                deps = []
                if hasattr(instance, "get_dependencies"):
                    try:
                        deps = list(instance.get_dependencies())
                    except Exception:
                        deps = []

                ref = PrestStageModuleRef(
                    prestage_id=prestage_id,
                    module_path=module_path,
                    description=str(info.get("description") or info.get("name") or prestage_id),
                    platforms=platforms,
                    languages=languages,
                    dependencies=deps,
                )
                _register_ref(ref)

    _loaded = True
    return dict(_catalog)


def reload_prestage_modules() -> Dict[str, PrestStageModuleRef]:
    global _loaded
    _loaded = False
    _loader.invalidate_discovery_cache()
    return discover_prestage_modules(force=True)


def list_prestage_refs(platform: Optional[str] = None, language: Optional[str] = None) -> List[PrestStageModuleRef]:
    catalog = discover_prestage_modules()
    lang = str(language or "").strip().lower()
    merged: Dict[str, PrestStageModuleRef] = {}
    seen_paths: Set[str] = set()

    for ref in catalog.values():
        if ref.module_path in seen_paths:
            continue
        if not ref.module_path.startswith("prestage/"):
            continue
        seen_paths.add(ref.module_path)
        if platform and not ref.matches_platform(platform):
            continue
        if lang and lang not in ref.languages:
            continue

        existing = merged.get(ref.prestage_id)
        if existing is None:
            merged[ref.prestage_id] = PrestStageModuleRef(
                prestage_id=ref.prestage_id,
                module_path=ref.module_path,
                description=ref.description,
                platforms=set(ref.platforms),
                languages=set(ref.languages),
                dependencies=list(ref.dependencies),
            )
            continue

        existing.platforms |= ref.platforms
        existing.languages |= ref.languages
        for dep in ref.dependencies:
            if dep not in existing.dependencies:
                existing.dependencies.append(dep)

    return sorted(merged.values(), key=lambda item: item.prestage_id)


def get_prestage_ref(name: str, language: Optional[str] = None) -> Optional[PrestStageModuleRef]:
    catalog = discover_prestage_modules()
    key = _normalize_key(name)
    lang = str(language or "").strip().lower()

    by_lang = _catalog_by_id.get(key)
    if by_lang:
        if lang and lang in by_lang:
            return by_lang[lang]
        if len(by_lang) == 1:
            return next(iter(by_lang.values()))

    ref = catalog.get(key)
    if ref is not None:
        if lang:
            try:
                return _pick_ref_for_language(ref, lang)
            except ValueError:
                return None
        return ref

    module_path = _resolve_module_path(key)
    if module_path:
        ref = catalog.get(module_path)
        if ref is None:
            return None
        if lang:
            try:
                return _pick_ref_for_language(ref, lang)
            except ValueError:
                return None
        return ref
    return None


def load_prestage_instance(module_path: str, framework=None):
    return _loader.load_module(module_path, framework=framework, silent=True, fast=True)


def materialize_prestage(
    name: str,
    *,
    language: str = "python",
    platform: str = "all",
    framework=None,
    context: Optional[dict] = None,
) -> MaterializedPrestage:
    lang = str(language or "python").strip().lower()
    ref = get_prestage_ref(name, language=lang)
    if ref is None:
        raise KeyError(f"Unknown prestage module: {name}")
    ref = _pick_ref_for_language(ref, lang)
    if not ref.matches_platform(platform):
        raise ValueError(
            f"Prestage '{ref.prestage_id}' is not compatible with platform '{platform}' "
            f"(supports: {', '.join(sorted(ref.platforms))})"
        )
    if lang not in ref.languages:
        raise ValueError(
            f"Prestage '{ref.prestage_id}' does not support language '{lang}' "
            f"(supported: {', '.join(sorted(ref.languages))})"
        )

    instance = load_prestage_instance(ref.module_path, framework=framework)
    if instance is None:
        raise RuntimeError(f"Could not load prestage module: {ref.module_path}")

    code = instance.generate(language=lang, context=dict(context or {}))
    return MaterializedPrestage(
        prestage_id=ref.prestage_id,
        module_path=ref.module_path,
        description=ref.description,
        code=code,
        platforms=set(ref.platforms),
        dependencies=list(ref.dependencies),
    )


def resolve_prestage_names(
    names: List[str],
    *,
    language: str = "python",
    platform: str = "all",
    framework=None,
    context: Optional[dict] = None,
) -> List[MaterializedPrestage]:
    discover_prestage_modules()
    resolved: List[MaterializedPrestage] = []
    seen: Set[str] = set()
    queue = [_normalize_key(name) for name in names if _normalize_key(name)]

    while queue:
        key = queue.pop(0)
        ref = get_prestage_ref(key, language=language)
        if ref is None:
            raise KeyError(f"Unknown prestage module: {key}")
        ref = _pick_ref_for_language(ref, language)
        token = ref.module_path
        if token in seen:
            continue
        item = materialize_prestage(
            ref.module_path,
            language=language,
            platform=platform,
            framework=framework,
            context=context,
        )
        seen.add(token)
        resolved.append(item)
        for dep in item.dependencies:
            dep_key = _normalize_key(dep)
            if dep_key and dep_key not in seen:
                queue.append(dep_key)
    return resolved
