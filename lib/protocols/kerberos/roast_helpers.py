#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared helpers for native Kerberos roast post modules."""

from __future__ import annotations

from typing import Any, Optional, Tuple

from lib.protocols.kerberos.roast import parse_domain_user


def session_host_and_creds(module) -> Tuple[str, str, str]:
    """Return (kdc_host, bind_user, bind_password) from LDAP session data."""
    host = user = password = ""
    try:
        sid = ""
        if hasattr(module, "session_id"):
            attr = getattr(module, "session_id")
            sid = str(getattr(attr, "value", attr) or "").strip()
        sm = getattr(getattr(module, "framework", None), "session_manager", None)
        sess = sm.get_session(sid) if sm and sid else None
        data = getattr(sess, "data", None) or {}
        if isinstance(data, dict):
            host = str(data.get("host") or "").strip()
            user = str(data.get("username") or "").strip()
            password = str(data.get("password") or "")
    except Exception:
        pass
    return host, user, password


def resolve_kdc(module, opt_dc_ip: str = "") -> str:
    explicit = str(opt_dc_ip or "").strip()
    if explicit:
        return explicit
    host, _, _ = session_host_and_creds(module)
    return host


def resolve_auth(
    module,
    *,
    username: str = "",
    password: str = "",
    nthash: str = "",
    domain: str = "",
) -> Tuple[str, str, str, str]:
    """Return (user, domain, password, nthash) merging opts + LDAP session."""
    host, sess_user, sess_pass = session_host_and_creds(module)
    _ = host
    user = str(username or "").strip() or sess_user
    pwd = str(password or "") if str(password or "") else sess_pass
    nt = str(nthash or "").strip()
    dom = str(domain or "").strip() or str(getattr(module, "domain", "") or "")
    sam, realm = parse_domain_user(user, dom)
    return sam, realm, pwd, nt
