#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Registry facade for offline prestage modules (modules/prestage/)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Set

from core.payload_generation.prestage_loader import (
    MaterializedPrestage,
    PrestStageModuleRef,
    discover_prestage_modules,
    get_prestage_ref,
    list_prestage_refs,
    materialize_prestage,
    reload_prestage_modules,
    resolve_prestage_names,
)


@dataclass
class Scriptlet:
    """Backward-compatible view of a materialized prestage snippet."""

    name: str
    description: str
    platforms: Set[str] = field(default_factory=lambda: {"all"})
    source_path: str = ""
    code: str = ""
    dependencies: List[str] = field(default_factory=list)
    module_path: str = ""

    @classmethod
    def from_ref(cls, ref: PrestStageModuleRef) -> "Scriptlet":
        return cls(
            name=ref.prestage_id,
            description=ref.description,
            platforms=set(ref.platforms),
            source_path=ref.module_path,
            module_path=ref.module_path,
            dependencies=list(ref.dependencies),
        )

    @classmethod
    def from_materialized(cls, item: MaterializedPrestage) -> "Scriptlet":
        return cls(
            name=item.prestage_id,
            description=item.description,
            platforms=set(item.platforms),
            source_path=item.module_path,
            module_path=item.module_path,
            code=item.code,
            dependencies=list(item.dependencies),
        )

    def matches_platform(self, platform: str) -> bool:
        from core.payload_generation.prestage_loader import _platform_compatible

        return _platform_compatible(platform, self.platforms)


def reload_scriptlets() -> None:
    reload_prestage_modules()


def get_scriptlet(name: str) -> Optional[Scriptlet]:
    ref = get_prestage_ref(name)
    if ref is None:
        return None
    return Scriptlet.from_ref(ref)


def list_scriptlets(platform: Optional[str] = None, language: Optional[str] = None) -> List[Scriptlet]:
    return [Scriptlet.from_ref(ref) for ref in list_prestage_refs(platform=platform, language=language)]


def resolve_scriptlet_names(
    names: List[str],
    platform: str = "all",
    *,
    language: str = "python",
    framework=None,
    context: Optional[dict] = None,
) -> List[Scriptlet]:
    items = resolve_prestage_names(
        names,
        language=language,
        platform=platform,
        framework=framework,
        context=context,
    )
    return [Scriptlet.from_materialized(item) for item in items]


__all__ = [
    "Scriptlet",
    "discover_prestage_modules",
    "get_scriptlet",
    "list_scriptlets",
    "materialize_prestage",
    "reload_scriptlets",
    "resolve_scriptlet_names",
]
