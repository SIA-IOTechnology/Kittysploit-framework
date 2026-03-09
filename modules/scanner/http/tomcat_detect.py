#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection Apache Tomcat."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Apache Tomcat detection",
        "description": "Detects if Apache Tomcat is installed (default page or manager).",
        "author": "KittySploit Team",
        "severity": "info",
        "modules": [],
        "tags": ["web", "scanner", "tomcat", "java", "manager"],
    }

    def run(self):
        for path in ["/", "/manager/html", "/manager/", "/host-manager/"]:
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            t = r.text.lower()
            if "apache tomcat" in t or "tomcat" in t and ("manager" in t or "administration" in t):
                return True
        return False
