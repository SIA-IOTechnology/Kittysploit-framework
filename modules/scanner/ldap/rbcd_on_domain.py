#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect RBCD on the domain object (full domain compromise path)."""

from kittysploit import *
from lib.protocols.ldap.ad_client import Ad_client

class Module(Scanner, Ad_client):
    __info__ = {
        "name": "AD RBCD on domain object",
        "description": "Detects msDS-AllowedToActOnBehalfOfOtherIdentity on domain NC (critical).",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["ad", "ldap", "scanner", "rbcd", "delegation", "domain"],
    }

    def run(self):
        dom = self.get_domain_object()
        if not dom:
            return False
        rbcd = self.attr_list(dom, "msDS-AllowedToActOnBehalfOfOtherIdentity")
        if not rbcd:
            return False
        self.set_info(severity="high", reason="RBCD set on domain object (any principal in ACL can impersonate any user)")
        return True
