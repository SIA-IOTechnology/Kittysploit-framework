#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""SSID-based password mutations for WPA CPU cracking."""

from __future__ import annotations

from typing import Iterable

DEFAULT_TOP = (
    "12345678",
    "password",
    "1234567890",
    "123456789",
    "qwerty123",
    "admin123",
    "internet",
    "wireless",
    "00000000",
)


def ssid_variants(ssid: str) -> list[str]:
    base = str(ssid or "").strip()
    if not base:
        return list(DEFAULT_TOP)
    out = [
        base,
        base.lower(),
        base.upper(),
        f"{base}123",
        f"{base}1234",
        f"{base}2024",
        f"{base}2025",
        f"{base}!",
        f"wifi{base}",
    ]
    seen: set[str] = set()
    merged: list[str] = []
    for entry in out + list(DEFAULT_TOP):
        if entry not in seen and 8 <= len(entry.encode()) <= 63:
            seen.add(entry)
            merged.append(entry)
    return merged


def merge_wordlists(*sources: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for source in sources:
        for line in source:
            text = str(line).strip()
            if text and text not in seen:
                seen.add(text)
                out.append(text)
    return out