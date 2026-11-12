#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Erlang/OTP SSH banner classification (CVE-2025-32433 chain)."""

from __future__ import annotations

_NON_ERLANG_SSH_MARKERS = (
    "openssh",
    "libssh",
    "dropbear",
    "cisco",
    "fortinet",
    "fips",
    "comware",
    "huawei",
    "paramiko",
)


def is_erlang_otp_ssh_banner(banner: str) -> bool:
    """True when the SSH identification string looks like Erlang/OTP SSH."""
    text = (banner or "").strip()
    low = text.lower()
    if not low.startswith("ssh-"):
        return False
    if any(marker in low for marker in _NON_ERLANG_SSH_MARKERS):
        return False
    if "erlang" in low:
        return True
    if "ssh-2.0-erlang" in low.replace(" ", ""):
        return True
    return False
