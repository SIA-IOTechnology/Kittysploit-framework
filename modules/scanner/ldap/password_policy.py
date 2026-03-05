#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check AD password policy (min length, lockout, history, reversible encryption)."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client
from lib.protocols.ldap.ad_helpers import filetime_100ns_to_days

class Module(Scanner, Ad_client):
    __info__ = {
        "name": "AD password policy",
        "description": "Detects weak domain password policy (min length, lockout, history, reversible encryption).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["ad", "ldap", "scanner", "password", "policy"],
    }

    def run(self):
        dom = self.get_domain_object()
        if not dom:
            return False
        min_len = self.attr_int(dom, "minPwdLength")
        history = self.attr_int(dom, "pwdHistoryLength")
        lockout = self.attr_int(dom, "lockoutThreshold")
        max_age = filetime_100ns_to_days(self.attr_int(dom, "maxPwdAge", -1))
        pwd_props = self.attr_int(dom, "pwdProperties")
        issues = []
        if min_len < 8:
            issues.append(f"min length {min_len} (< 8)")
        if history < 10:
            issues.append(f"history {history} (< 24 recommended)")
        if lockout == 0:
            issues.append("no lockout")
        if max_age == 0:
            issues.append("passwords never expire")
        if pwd_props & 16:
            issues.append("reversible encryption enabled")
        if not (pwd_props & 1):
            issues.append("complexity disabled")
        if not issues:
            return False
        self.set_info(severity="medium", reason="; ".join(issues))
        return True
