#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Token-budgeted knowledge-base packing for LLM planning.

Replaces blind truncation with ranked, visible context assembly: every section
included or dropped is reported so the planner knows what was omitted.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

DEFAULT_TOKEN_BUDGET = 6000

# Security-relevant keywords boost ranking
_SECURITY_HINTS = frozenset({
    "auth", "login", "session", "admin", "sql", "sqli", "xss", "lfi", "ssrf",
    "rce", "shell", "upload", "csrf", "jwt", "cookie", "waf", "redirect",
    "modbus", "s7", "plc", "ics", "ldap", "kerberos", "smb",
})


def estimate_tokens(text: Any) -> int:
    """Approximate token count (chars / 4) for budgeting — not a real tokenizer."""
    s = str(text or "")
    if not s:
        return 0
    return max(1, (len(s) + 3) // 4)


def _extract_keywords(*texts: Optional[str]) -> List[str]:
    words: set = set()
    for text in texts:
        if not text:
            continue
        for token in str(text).lower().replace("/", " ").replace("_", " ").split():
            token = token.strip(".,;:'\"()[]{}")
            if len(token) >= 3:
                words.add(token)
    return sorted(words)


def _score_section(name: str, content: Any, keywords: Sequence[str]) -> float:
    blob = f"{name} {content}".lower()
    score = 0.0
    for kw in keywords:
        if kw in blob:
            score += 1.5
    for hint in _SECURITY_HINTS:
        if hint in blob:
            score += 0.8
    # Prefer actionable sections
    if name in {"risk_signals", "unlocked_capabilities", "login_paths", "tech_confidence"}:
        score += 2.0
    if name in {"discovered_endpoints", "discovered_params"}:
        score += 1.0
    return score


def _serialize_section(name: str, content: Any, *, max_items: int = 20) -> str:
    if content is None:
        return ""
    if isinstance(content, dict):
        if name == "tech_confidence":
            rows = sorted(content.items(), key=lambda r: float(r[1] or 0), reverse=True)
            return "\n".join(f"  {k}: {float(v or 0):.2f}" for k, v in rows[:max_items])
        lines = []
        for k, v in list(content.items())[:max_items]:
            lines.append(f"  {k}: {_truncate_value(v, 120)}")
        return "\n".join(lines)
    if isinstance(content, (list, tuple, set)):
        items = list(content)[:max_items]
        return "\n".join(f"  - {_truncate_value(item, 160)}" for item in items)
    return _truncate_value(content, 800)


def _truncate_value(value: Any, limit: int) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def pack_knowledge_context(
    kb: Mapping[str, Any],
    *,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
    objective: str = "",
    prior_intel: str = "",
    extra_sections: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Assemble a token-budgeted knowledge context for LLM planning.

    Returns packed text plus telemetry on included/dropped sections.
    """
    if not isinstance(kb, dict):
        kb = {}
    budget = max(500, int(token_budget or DEFAULT_TOKEN_BUDGET))
    keywords = _extract_keywords(objective, prior_intel, str(kb.get("campaign_goal", "")))

    # Candidate sections from knowledge base
    candidates: List[Tuple[str, Any]] = [
        ("tech_hints", kb.get("tech_hints", [])),
        ("tech_confidence", kb.get("tech_confidence", {})),
        ("risk_signals", kb.get("risk_signals", [])),
        ("specializations", kb.get("specializations", [])),
        ("login_paths", kb.get("login_paths", [])),
        ("discovered_endpoints", kb.get("discovered_endpoints", [])),
        ("discovered_params", kb.get("discovered_params", [])),
        ("observed_modules", kb.get("observed_modules", [])),
        ("unlocked_capabilities", kb.get("unlocked_capabilities", [])),
    ]
    if extra_sections:
        for name, content in extra_sections.items():
            candidates.append((str(name), content))

    # Always include a compact map header
    map_lines = [
        f"KB MAP ({len(candidates)} sections, budget={budget} tokens approx)",
    ]
    for name, content in candidates:
        size_hint = len(content) if isinstance(content, (list, dict)) else len(str(content or ""))
        map_lines.append(f"  [{name}] items/size={size_hint}")
    header = "\n".join(map_lines)
    header_tokens = estimate_tokens(header)

    ranked = sorted(
        candidates,
        key=lambda row: _score_section(row[0], row[1], keywords),
        reverse=True,
    )

    included: List[str] = []
    dropped: List[str] = []
    body_parts: List[str] = []
    used = header_tokens

    for name, content in ranked:
        if content is None or content == [] or content == {}:
            dropped.append(name)
            continue
        section_text = f"## {name}\n{_serialize_section(name, content)}"
        section_tokens = estimate_tokens(section_text)
        if used + section_tokens > budget:
            dropped.append(name)
            continue
        body_parts.append(section_text)
        included.append(name)
        used += section_tokens

    text = header + "\n\n" + "\n\n".join(body_parts) if body_parts else header
    return {
        "text": text.strip(),
        "included_sections": included,
        "dropped_sections": dropped,
        "tokens_used": used,
        "token_budget": budget,
        "keywords": keywords[:24],
    }
