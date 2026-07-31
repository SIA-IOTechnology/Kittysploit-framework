# -*- coding: utf-8 -*-
"""Active Directory LDAP enumeration helpers (NetExec-style)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


UAC_ACCOUNTDISABLE = 2


def filetime_to_str(value: Any) -> str:
    """Convert Windows FILETIME / ldap3 datetime to display string."""
    if value is None or value == "":
        return "<never>"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    try:
        ft = int(value)
    except (TypeError, ValueError):
        return str(value)[:32]
    if ft in (0, 9223372036854775807):
        return "<never>"
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ft)


def is_account_disabled(uac: int) -> bool:
    return bool(int(uac or 0) & UAC_ACCOUNTDISABLE)


def user_row(client: Any, entry: Any) -> Dict[str, Any]:
    """Normalize a user LDAP entry for table-style output."""
    uac = client.attr_int(entry, "userAccountControl", 0)
    pwd = getattr(entry, "pwdLastSet", None)
    pwd_val = pwd.value if hasattr(pwd, "value") else pwd
    return {
        "sam": client.attr_str(entry, "sAMAccountName"),
        "dn": getattr(entry, "entry_dn", "") or client.attr_str(entry, "distinguishedName"),
        "admin_count": client.attr_int(entry, "adminCount", 0),
        "bad_pwd_count": client.attr_int(entry, "badPwdCount", 0),
        "pwd_last_set": filetime_to_str(pwd_val),
        "uac": uac,
        "disabled": is_account_disabled(uac),
        "description": client.attr_str(entry, "description"),
        "memberof": [str(x) for x in client.attr_list(entry, "memberOf")],
    }


USER_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "adminCount",
    "badPwdCount",
    "pwdLastSet",
    "userAccountControl",
    "description",
    "memberOf",
]


def enumerate_users(client: Any, *, active_only: bool = False, admin_count_only: bool = False) -> List[Dict[str, Any]]:
    filt = "(&(objectCategory=person)(objectClass=user))"
    if admin_count_only:
        filt = "(&(objectCategory=person)(objectClass=user)(adminCount=1))"
    entries = client.search(filt, USER_ATTRS) or []
    rows = [user_row(client, e) for e in entries]
    rows = [r for r in rows if r.get("sam")]
    if active_only:
        rows = [r for r in rows if not r.get("disabled")]
    rows.sort(key=lambda r: str(r.get("sam") or "").lower())
    return rows


def group_members(client: Any, group_name: str) -> List[str]:
    """Return sAMAccountName (or CN) for members of a named group."""
    name = str(group_name or "").strip()
    if not name:
        return []
    esc = (
        name.replace("\\", "\\5c")
        .replace("*", "\\2a")
        .replace("(", "\\28")
        .replace(")", "\\29")
    )
    groups = client.search(
        f"(&(objectClass=group)(|(sAMAccountName={esc})(cn={esc})(name={esc})))",
        ["member", "sAMAccountName", "cn"],
        size_limit=5,
    ) or []
    if not groups:
        return []
    members = client.attr_list(groups[0], "member")
    out: List[str] = []
    for dn in members:
        dn_s = str(dn)
        # Resolve DN to sam
        try:
            rows = client.search(
                f"(distinguishedName={dn_s})",
                ["sAMAccountName", "cn"],
                size_limit=1,
            )
            if rows:
                sam = client.attr_str(rows[0], "sAMAccountName") or client.attr_str(rows[0], "cn")
                out.append(sam or dn_s)
            else:
                # Fallback: CN= from DN
                out.append(dn_s.split(",")[0].replace("CN=", "").replace("cn=", ""))
        except Exception:
            out.append(dn_s)
    return out


def user_group_membership(client: Any, username: str) -> List[str]:
    """Groups that list *username* as member (via memberOf + primary group)."""
    sam = str(username or "").strip()
    if not sam:
        return []
    esc = (
        sam.replace("\\", "\\5c")
        .replace("*", "\\2a")
        .replace("(", "\\28")
        .replace(")", "\\29")
    )
    users = client.search(
        f"(&(objectClass=user)(sAMAccountName={esc}))",
        ["memberOf", "primaryGroupID", "objectSid"],
        size_limit=1,
    ) or []
    if not users:
        return []
    groups = [str(x) for x in client.attr_list(users[0], "memberOf")]
    # Pretty: extract CN=
    pretty = []
    for g in groups:
        if g.upper().startswith("CN="):
            pretty.append(g.split(",")[0][3:])
        else:
            pretty.append(g)
    return pretty
