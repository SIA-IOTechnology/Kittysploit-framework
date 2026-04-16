#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Precompiled regexes for hot paths in :class:`AgentWorkflowCore` (avoid per-call compilation)."""

from __future__ import annotations

import re

# --- Adaptive keywords & post-auth lexical tokens ---

WORD_RE = re.compile(r"\b[a-z][a-z0-9_-]{3,24}\b")

POST_AUTH_WORD_RE = re.compile(r"\b[a-z][a-z0-9_]{3,}\b")
ACRONYM_RE = re.compile(r"\b[a-z]{2,3}\b")

# --- Strip HTML noise before token extraction ---

SCRIPT_RE = re.compile(r"(?is)<script[^>]*>.*?</script>")
STYLE_RE = re.compile(r"(?is)<style[^>]*>.*?</style>")
TAG_RE = re.compile(r"<[^>]+>")

# --- Knowledge base / campaign parsing ---

HTTP_STATUS_IN_TEXT_RE = re.compile(r"status\s+(\d{3})", re.IGNORECASE)

LOGIN_PAGE_PATH_IN_MESSAGE_RE = re.compile(
    r"login page detected on\s+(/\S+)",
    re.IGNORECASE,
)

COMMA_SEMICOLON_SPLIT_RE = re.compile(r"[,;]")

# --- Endpoint & param discovery ---

ABSOLUTE_URL_RE = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)

ENDPOINT_RE = re.compile(r"(?:^|[\s(])(/[\w\-./%]+(?:\?[\w\-./%=&]+)?)")

PARAM_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]{1,40})=([^&\s]+)")
