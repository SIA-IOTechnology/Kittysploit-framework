#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection interfaces de gestion télécom (eNodeB/gNodeB, OSS, équipementiers)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


# Paths / keywords typiques des interfaces de gestion (Huawei, Ericsson, Nokia, ZTE, etc.)
PATHS = [
    "/",
    "/admin",
    "/login",
    "/webui",
    "/oss",
    "/bsc",
    "/enodeb",
    "/gnodeb",
    "/lte",
    "/5g",
    "/ne",
    "/ems",
    "/omc",
    "/mme",
]


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Telecom management interface detection",
        "description": "Detects telecom / 5G management UIs (eNodeB, gNodeB, OSS, vendor panels).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["telecom", "scanner", "5g", "lte", "management", "oss", "ran", "huawei", "ericsson", "nokia"],
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r:
            return False
        t = r.text.lower()
        # Marques / mots-clés typiques des interfaces de gestion mobile
        keywords = [
            "huawei", "ericsson", "nokia", "zte", "samsung", "cisco",
            "enodeb", "gnodeb", "enb", "gnb", "ran", "lte", "5g", "nr",
            "oss", "bsc", "rnc", "mme", "hss", "epc", "5gc", "core network",
            "element manager", "network manager", "radio access",
        ]
        for kw in keywords:
            if kw in t:
                self.set_info(severity="medium", reason=f"Telecom/5G management keyword: {kw}")
                return True
        for path in ["/admin", "/webui", "/oss", "/omc"]:
            r2 = self.http_request(method="GET", path=path, allow_redirects=False)
            if r2 and r2.status_code == 200 and len(r2.text) > 100:
                if any(k in r2.text.lower() for k in ["login", "password", "admin", "lte", "5g", "radio"]):
                    self.set_info(severity="medium", reason=f"Management-like path: {path}")
                    return True
        return False
