#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Tomcat Manager default login."""

import base64

from kittysploit import *
from lib.protocols.http.http_client import Http_client


# Common Tomcat Manager credential pairs
CREDS = (
    ("tomcat", "tomcat"),
    ("admin", "admin"),
    ("admin", "manager"),
    ("admin", "s3cret"),
    ("admin", "changethis"),
    ("admin", "tomcat"),
    ("manager", "manager"),
    ("role1", "role1"),
    ("role1", "tomcat"),
    ("root", "root"),
    ("root", "r00t"),
    ("both", "tomcat"),
    ("ADMIN", "ADMIN"),
    ("ovwebusr", "OvW*busr1"),
    ("j2deployer", "j2deployer"),
    ("cxsdk", "kdsxc"),
    ("QCC", "QLogic66"),
    ("xampp", "xampp"),
    ("demo", "demo"),
    ("server_admin", "owaspbwa"),
    ("role", "changethis"),
    ("tomcat", "s3cret"),
    ("tomcat", "changethis"),
    ("tomcat", "Password1"),
    ("vagrant", "vagrant"),
    ("admin", "password"),
    ("admin", "Password1"),
    ("admin", "admin123"),
)

PATHS = (
    "/manager/html",
    "/manager/html/",
    "/tomcat/manager/html",
    "/host-manager/html",
)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Tomcat Manager Default Login",
        "description": (
            "Detects Apache Tomcat Manager default credentials via HTTP Basic."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": [
            "https://www.rapid7.com/db/vulnerabilities/apache-tomcat-default-ovwebusr-password/",
        ],
        "tags": ["web", "scanner", "tomcat", "apache", "default-login", "vuln"],
        "modules": ["scanner/http/tomcat_manager_detect"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "credential_testing"],
            "expected_requests": 30,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "credentials"],
            "cost": 1.4,
            "noise": 0.7,
            "value": 1.5,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [{"capability": "admin_surface", "from_detail": ""}],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    def _url(self, path: str) -> str:
        host = str(getattr(getattr(self, "target", None), "value", getattr(self, "target", "")) or "").strip()
        port = getattr(getattr(self, "port", None), "value", getattr(self, "port", 80))
        ssl = getattr(getattr(self, "ssl", None), "value", getattr(self, "ssl", False))
        scheme = "https" if ssl in (True, "true", "True", 1, "1") else "http"
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            port_i = 443 if scheme == "https" else 80
        if host.startswith(("http://", "https://")):
            return host.rstrip("/") + path
        return f"{scheme}://{host}:{port_i}{path}"

    def run(self):
        for path in PATHS:
            for username, password in CREDS:
                token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=False,
                    headers={"Authorization": f"Basic {token}"},
                )
                if not response or response.status_code != 200:
                    continue
                body = response.text or ""
                if "Apache Tomcat" not in body or "Server Information" not in body:
                    continue
                markers = (
                    "Tomcat Version",
                    "JVM Version",
                    "JVM Vendor",
                    "OS Name",
                    "OS Version",
                    "OS Architecture",
                    "Hostname",
                    "IP Address",
                )
                if not any(marker in body for marker in markers):
                    continue

                self.report_finding(
                    "Tomcat Manager default credentials accepted",
                    severity="high",
                    evidence={
                        "url": self._url(path),
                        "status_code": 200,
                        "path": path,
                        "username": username,
                        "password": password,
                    },
                    impact={
                        "summary": "Authenticated access to Tomcat Manager enables WAR deploy / RCE.",
                        "business_risk": "Remote code execution via application deployment",
                    },
                    remediation={
                        "summary": "Remove default Manager accounts and lock down the Manager app.",
                        "actions": [
                            "Change or delete default tomcat-users.xml credentials",
                            "Restrict /manager to trusted networks",
                            "Disable Manager application if unused",
                        ],
                    },
                )
                return True
        return False
