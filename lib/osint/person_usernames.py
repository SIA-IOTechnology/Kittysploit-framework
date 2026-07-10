#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Derive likely usernames from a person's name, display name, and aliases."""

from __future__ import annotations

import re
import unicodedata
from typing import Any


def slug_token(value: str) -> str:
    """Normalize a name fragment to an ASCII lowercase username token."""
    normalized = unicodedata.normalize("NFKD", value)
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "", ascii_only.lower())


def coerce_name_list(raw: object) -> list[str]:
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        if "," in text:
            return [part.strip() for part in text.split(",") if part.strip()]
        return [text]
    if isinstance(raw, list):
        return [item.strip() for item in raw if isinstance(item, str) and item.strip()]
    return []


def generate_username_patterns(candidate_name: str) -> list[tuple[str, float, str]]:
    """Return (username, confidence, rationale) tuples for a candidate name."""
    parts = [part for part in re.split(r"[\s._-]+", candidate_name.strip()) if part]
    if not parts:
        return []

    first = slug_token(parts[0])
    last = slug_token(parts[-1]) if len(parts) > 1 else ""
    middle_initial = slug_token(parts[1])[0:1] if len(parts) > 2 and slug_token(parts[1]) else ""

    base_tokens = [slug_token(part) for part in parts]
    base_tokens = [token for token in base_tokens if token]
    if not base_tokens:
        return []

    results: list[tuple[str, float, str]] = []

    if len(base_tokens) == 1:
        token = base_tokens[0]
        if len(token) >= 3:
            results.append((token, 0.5, "derived_from_single_name"))
        return results

    full_joined = "".join(base_tokens)
    first_last = f"{first}{last}"
    first_dot_last = f"{first}.{last}"
    first_underscore_last = f"{first}_{last}"
    first_initial_last = f"{first[:1]}{last}"
    last_first_initial = f"{last}{first[:1]}"
    first_last_initial = f"{first}{last[:1]}"
    first_initial_middle_last = f"{first[:1]}{middle_initial}{last}" if middle_initial else ""

    patterns = [
        (first_last, 0.62, "derived_from_name_pattern:firstlast"),
        (first_dot_last, 0.6, "derived_from_name_pattern:first.last"),
        (first_underscore_last, 0.58, "derived_from_name_pattern:first_last"),
        (first_initial_last, 0.57, "derived_from_name_pattern:flast"),
        (last_first_initial, 0.54, "derived_from_name_pattern:lastf"),
        (first_last_initial, 0.52, "derived_from_name_pattern:firstl"),
        (full_joined, 0.5, "derived_from_name_pattern:fulljoined"),
    ]
    if first_initial_middle_last:
        patterns.append((first_initial_middle_last, 0.53, "derived_from_name_pattern:fmlast"))

    for username, confidence, rationale in patterns:
        if len(username) >= 3:
            results.append((username, confidence, rationale))
    return results


def build_candidate_names(
    *,
    name: str = "",
    first_name: str = "",
    last_name: str = "",
    display_name: str = "",
    aliases: object = None,
) -> list[tuple[str, str]]:
    """Collect raw name strings and their source labels."""
    candidates: list[tuple[str, str]] = []

    entity_value = str(name or "").strip()
    first_name = str(first_name or "").strip()
    last_name = str(last_name or "").strip()
    display_name = str(display_name or "").strip()
    alias_values = coerce_name_list(aliases)

    if entity_value:
        candidates.append((entity_value, "entity_value"))
    if display_name:
        candidates.append((display_name, "display_name"))
    if first_name and last_name:
        candidates.append((f"{first_name} {last_name}", "first_last_name"))
    alias_values = [alias.strip() for alias in alias_values if alias.strip()]
    candidates.extend((alias, "alias") for alias in alias_values)

    return candidates


def generate_person_usernames(
    *,
    name: str = "",
    first_name: str = "",
    last_name: str = "",
    display_name: str = "",
    aliases: object = None,
    max_results: int = 10,
) -> dict[str, Any]:
    """Generate scored username candidates from person identity fields."""
    candidate_names = build_candidate_names(
        name=name,
        first_name=first_name,
        last_name=last_name,
        display_name=display_name,
        aliases=aliases,
    )

    if not candidate_names:
        return {
            "person": str(name or "").strip(),
            "skipped": True,
            "reason": "no_name_data",
            "messages": ["Not enough person name data to derive username candidates."],
            "count": 0,
            "candidates": [],
        }

    generated: dict[str, tuple[float, str]] = {}
    for raw_name, source in candidate_names:
        for username, confidence, rationale in generate_username_patterns(raw_name):
            existing = generated.get(username)
            enriched_rationale = f"{rationale};source={source}"
            if existing is None or confidence > existing[0]:
                generated[username] = (confidence, enriched_rationale)

    ranked = sorted(
        generated.items(),
        key=lambda item: (-item[1][0], item[0]),
    )[: max(1, max_results)]

    candidates = [
        {
            "username": username,
            "confidence": round(confidence, 2),
            "rationale": rationale,
        }
        for username, (confidence, rationale) in ranked
    ]

    messages: list[str]
    if candidates:
        messages = [f"Generated {len(candidates)} likely username candidate(s)."]
    else:
        messages = ["Not enough person name data to derive username candidates."]

    return {
        "person": str(name or display_name or f"{first_name} {last_name}".strip()).strip(),
        "skipped": not bool(candidates),
        "reason": "" if candidates else "no_patterns",
        "messages": messages,
        "count": len(candidates),
        "candidates": candidates,
    }
