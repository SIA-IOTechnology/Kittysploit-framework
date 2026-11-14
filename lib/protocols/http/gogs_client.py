#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gogs HTTP fingerprint and version helpers."""

from __future__ import annotations

import re
from typing import Optional, Tuple

from core.framework.base_module import BaseModule

COMMIT_TO_VERSION = {
    "3ba8aca90e17e5410b7e8b227c9f29256ac3e875": "0.14.3",
    "5dcb6c64bdf61e38dbdbb941c1d69789c560d0fb": "0.14.2",
    "f5c8030c1fd936f3e0e9f774e3c7c39fd102f56f": "0.14.1",
    "36c26c4ccc3ca0339db53eb1fa41e4e86b55163d": "0.14.0",
    "5084b4a9b77a506f5e287e82e945e1c6882b827a": "0.13.3",
}

_GOGS_META = re.compile(r'<meta\s+name="author"\s+content="Gogs"', re.I)
_CSS_HASH = re.compile(r"gogs\.min\.css\?v=([a-f0-9]{40})")


class Gogs(BaseModule):
    """Gogs fingerprint mixin for scanner and exploit modules."""

    @staticmethod
    def is_gogs_page(body: str) -> bool:
        return bool(_GOGS_META.search(body or ""))

    @classmethod
    def version_from_body(cls, body: str) -> Tuple[Optional[str], str]:
        text = body or ""
        match = _CSS_HASH.search(text)
        if not match:
            return None, ""
        commit = match.group(1)
        return COMMIT_TO_VERSION.get(commit), commit

    @staticmethod
    def version_tuple(version: str) -> Tuple[int, ...]:
        parts = []
        for token in str(version or "").split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        return tuple(parts)

    @classmethod
    def rebase_merge_vulnerable(cls, body: str) -> Tuple[bool, str, str]:
        if not cls.is_gogs_page(body):
            return False, "", "not gogs"
        version, commit = cls.version_from_body(body)
        if version:
            if cls.version_tuple(version) < (0, 14, 3):
                return True, version, commit
            return False, version, commit
        return True, "", commit or "unknown commit hash"


def gogs_rebase_vulnerable(body: str) -> Tuple[bool, str, str]:
    return Gogs.rebase_merge_vulnerable(body)