#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic BIND session hint strings for database/service listeners."""

from __future__ import annotations


def build_bind_session_hint(
    service: str,
    host: str,
    port: int,
    username: str = "",
    extra: str = "",
    probe: str = "",
) -> str:
    user = f" as {username}" if username else ""
    tail = f" {extra}" if extra else ""
    check = probe or f"# connect to {service}"
    return (
        f"# KittySploit {service} BIND session\n"
        f"# Framework listener connects to {host}:{port}{user}{tail}\n"
        f"# No reverse agent on target — use after credential discovery.\n"
        f"{check}"
    )
