#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""RTSP/1.0 client — OPTIONS, DESCRIBE, SETUP/PLAY (TCP interleaved), TEARDOWN."""

from __future__ import annotations

import hashlib
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse


RTSP_PORT = 554
RTSPS_PORT = 322


@dataclass
class RtspResponse:
    status: int = 0
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw: bytes = b""

    @property
    def ok(self) -> bool:
        return 200 <= int(self.status) < 300


@dataclass
class SdpMedia:
    media_type: str = ""
    port: int = 0
    proto: str = ""
    fmt: str = ""
    control: str = ""
    encoding: str = ""
    rtpmap: str = ""


@dataclass
class RtspDescribeResult:
    url: str = ""
    status: int = 0
    server: str = ""
    content_type: str = ""
    content_base: str = ""
    session_description: str = ""
    media: List[SdpMedia] = field(default_factory=list)
    auth_required: bool = False
    error: str = ""


def parse_rtsp_url(url: str, default_port: int = RTSP_PORT) -> Dict[str, object]:
    raw = str(url or "").strip()
    if not raw:
        return {"host": "", "port": default_port, "path": "/", "username": "", "password": "", "scheme": "rtsp"}
    if "://" not in raw:
        # host[:port][/path] or bare host
        if "/" in raw:
            hostpart, path = raw.split("/", 1)
            path = "/" + path
        else:
            hostpart, path = raw, "/"
        if ":" in hostpart and hostpart.count(":") == 1:
            host, port_s = hostpart.split(":", 1)
            port = int(port_s)
        else:
            host, port = hostpart, default_port
        return {
            "scheme": "rtsp",
            "host": host,
            "port": port,
            "path": path or "/",
            "username": "",
            "password": "",
        }
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "rtsp").lower()
    port = int(parsed.port or (RTSPS_PORT if scheme == "rtsps" else default_port))
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return {
        "scheme": scheme,
        "host": parsed.hostname or "",
        "port": port,
        "path": path,
        "username": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
    }


def _header_get(headers: Dict[str, str], name: str, default: str = "") -> str:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return default


def parse_sdp(body: str) -> List[SdpMedia]:
    media: List[SdpMedia] = []
    current: Optional[SdpMedia] = None
    for line in str(body or "").splitlines():
        line = line.strip()
        if line.startswith("m="):
            if current:
                media.append(current)
            parts = line[2:].split()
            current = SdpMedia(
                media_type=parts[0] if parts else "",
                port=int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                proto=parts[2] if len(parts) > 2 else "",
                fmt=" ".join(parts[3:]) if len(parts) > 3 else "",
            )
        elif current is None:
            continue
        elif line.startswith("a=control:"):
            current.control = line.split(":", 1)[1].strip()
        elif line.startswith("a=rtpmap:"):
            current.rtpmap = line.split(":", 1)[1].strip()
            # e.g. 96 H264/90000
            bits = current.rtpmap.split(None, 1)
            if len(bits) > 1:
                current.encoding = bits[1].split("/")[0]
    if current:
        media.append(current)
    return media


def _parse_www_authenticate(header: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if not header:
        return result
    scheme_match = re.match(r"\s*(\w+)\s*(.*)", header, re.I)
    if not scheme_match:
        return result
    result["scheme"] = scheme_match.group(1).lower()
    rest = scheme_match.group(2)
    for key, value in re.findall(r'(\w+)="([^"]*)"', rest):
        result[key.lower()] = value
    for key, value in re.findall(r"(\w+)=([^,\s]+)", rest):
        if key.lower() not in result:
            result[key.lower()] = value.strip('"')
    return result


def _md5_hex(data: str) -> str:
    return hashlib.md5(data.encode("utf-8")).hexdigest()


def build_digest_authorization(
    *,
    username: str,
    password: str,
    method: str,
    uri: str,
    challenge: Dict[str, str],
    nc: int = 1,
    cnonce: str = "kittysploit",
) -> str:
    realm = challenge.get("realm", "")
    nonce = challenge.get("nonce", "")
    qop = challenge.get("qop", "")
    opaque = challenge.get("opaque", "")
    algorithm = challenge.get("algorithm", "MD5")
    ha1 = _md5_hex(f"{username}:{realm}:{password}")
    ha2 = _md5_hex(f"{method}:{uri}")
    if qop:
        nc_value = f"{nc:08x}"
        response = _md5_hex(f"{ha1}:{nonce}:{nc_value}:{cnonce}:{qop.split(',')[0].strip()}:{ha2}")
        parts = [
            f'username="{username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{uri}"',
            f'response="{response}"',
            f'algorithm={algorithm}',
            f'qop={qop.split(",")[0].strip()}',
            f"nc={nc_value}",
            f'cnonce="{cnonce}"',
        ]
    else:
        response = _md5_hex(f"{ha1}:{nonce}:{ha2}")
        parts = [
            f'username="{username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{uri}"',
            f'response="{response}"',
            f'algorithm={algorithm}',
        ]
    if opaque:
        parts.append(f'opaque="{opaque}"')
    return "Digest " + ", ".join(parts)


def _parse_response(raw: bytes) -> RtspResponse:
    text = raw.decode("latin-1", errors="replace")
    if "\r\n\r\n" in text:
        head, body = text.split("\r\n\r\n", 1)
    else:
        head, body = text, ""
    lines = head.split("\r\n")
    status = 0
    reason = ""
    if lines:
        m = re.match(r"RTSP/\d\.\d\s+(\d+)\s*(.*)", lines[0])
        if m:
            status = int(m.group(1))
            reason = m.group(2).strip()
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return RtspResponse(status=status, reason=reason, headers=headers, body=body, raw=raw)


class RtspClient:
    """Session-oriented RTSP client (TCP, optional TLS for rtsps)."""

    def __init__(
        self,
        host: str = "",
        port: int = RTSP_PORT,
        path: str = "/",
        username: str = "",
        password: str = "",
        timeout: float = 5.0,
        url: str = "",
        use_tls: bool = False,
    ):
        if url:
            parts = parse_rtsp_url(url)
            self.host = str(parts["host"] or host)
            self.port = int(parts["port"] or port)
            self.path = str(parts["path"] or path or "/")
            self.username = str(parts["username"] or username or "")
            self.password = str(parts["password"] or password or "")
            self.use_tls = str(parts["scheme"]).lower() == "rtsps" or bool(use_tls)
        else:
            self.host = str(host or "").strip()
            self.port = int(port or RTSP_PORT)
            self.path = str(path or "/")
            if not self.path.startswith("/"):
                self.path = "/" + self.path
            self.username = str(username or "")
            self.password = str(password or "")
            self.use_tls = bool(use_tls)

        self.timeout = float(timeout)
        self._sock: Optional[socket.socket] = None
        self._cseq = 0
        self.session_id = ""
        self.session_timeout = 0
        self.content_base = ""
        self.last_options: List[str] = []
        self.last_sdp = ""
        self.last_media: List[SdpMedia] = []
        self.last_error = ""
        self.server = ""
        self.auth_challenge: Dict[str, str] = {}
        self._digest_nc = 1
        self.transport = ""
        self.playing = False

    @property
    def connected(self) -> bool:
        return self._sock is not None

    @property
    def request_uri(self) -> str:
        scheme = "rtsps" if self.use_tls else "rtsp"
        return f"{scheme}://{self.host}:{self.port}{self.path}"

    def connect(self) -> bool:
        self.close()
        self.last_error = ""
        if not self.host:
            self.last_error = "host required"
            return False
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            sock.settimeout(self.timeout)
            if self.use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
            self._sock = sock
        except OSError as exc:
            self.last_error = str(exc)
            return False

        resp = self.options()
        if resp.status == 401 and (self.username or self.password):
            resp = self.options()
        if not resp.ok and resp.status not in (200, 401):
            # Some cameras answer DESCRIBE-only; still keep socket if OPTIONS got RTSP framing
            if resp.status == 0:
                self.last_error = self.last_error or "no RTSP response"
                self.close()
                return False
        if resp.ok:
            public = _header_get(resp.headers, "Public") or _header_get(resp.headers, "Allow")
            self.last_options = [m.strip() for m in public.split(",") if m.strip()] if public else []
            self.server = _header_get(resp.headers, "Server")
        return True

    def close(self) -> None:
        if self._sock:
            try:
                if self.session_id:
                    try:
                        self.teardown()
                    except Exception:
                        pass
            finally:
                try:
                    self._sock.close()
                except Exception:
                    pass
        self._sock = None
        self.session_id = ""
        self.playing = False

    def _authorization(self, method: str, uri: str) -> str:
        if not self.username and not self.password:
            return ""
        if self.auth_challenge.get("scheme") == "digest":
            auth = build_digest_authorization(
                username=self.username,
                password=self.password,
                method=method,
                uri=uri,
                challenge=self.auth_challenge,
                nc=self._digest_nc,
            )
            self._digest_nc += 1
            return auth
        import base64

        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        return f"Basic {token}"

    def _send_request(
        self,
        method: str,
        uri: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        body: str = "",
    ) -> RtspResponse:
        if not self._sock:
            raise RuntimeError("not connected")
        target = uri or self.request_uri
        self._cseq += 1
        headers = {
            "CSeq": str(self._cseq),
            "User-Agent": "KittySploit-RTSP/1.0",
        }
        auth = self._authorization(method, target)
        if auth:
            headers["Authorization"] = auth
        if self.session_id and method not in {"OPTIONS"}:
            headers["Session"] = self.session_id
        if body:
            headers["Content-Length"] = str(len(body.encode("utf-8")))
            headers["Content-Type"] = "application/sdp"
        if extra_headers:
            headers.update(extra_headers)

        lines = [f"{method} {target} RTSP/1.0"]
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        lines.append(body)
        payload = "\r\n".join(lines).encode("utf-8")
        self._sock.sendall(payload)
        raw = self._recv_message()
        resp = _parse_response(raw)
        if resp.status == 401:
            www = _header_get(resp.headers, "WWW-Authenticate")
            self.auth_challenge = _parse_www_authenticate(www)
            if (self.username or self.password) and self.auth_challenge:
                # one retry with auth
                self._cseq += 1
                headers["CSeq"] = str(self._cseq)
                headers["Authorization"] = self._authorization(method, target)
                lines = [f"{method} {target} RTSP/1.0"]
                for key, value in headers.items():
                    lines.append(f"{key}: {value}")
                lines.append("")
                lines.append(body)
                self._sock.sendall("\r\n".join(lines).encode("utf-8"))
                raw = self._recv_message()
                resp = _parse_response(raw)
        session = _header_get(resp.headers, "Session")
        if session:
            self.session_id = session.split(";")[0].strip()
            m = re.search(r"timeout\s*=\s*(\d+)", session, re.I)
            if m:
                self.session_timeout = int(m.group(1))
        return resp

    def _recv_message(self) -> bytes:
        assert self._sock is not None
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                break
            # Skip interleaved RTP/RTCP ($...) frames if they arrive early
            if not buf and chunk.startswith(b"$"):
                if len(chunk) < 4:
                    chunk += self._sock.recv(4 - len(chunk))
                length = int.from_bytes(chunk[2:4], "big")
                need = 4 + length - len(chunk)
                while need > 0:
                    more = self._sock.recv(need)
                    if not more:
                        break
                    chunk += more
                    need = 4 + length - len(chunk)
                continue
            buf += chunk
            if len(buf) > 65536:
                break
        if b"\r\n\r\n" not in buf:
            return buf
        head, rest = buf.split(b"\r\n\r\n", 1)
        headers_text = head.decode("latin-1", errors="replace")
        content_length = 0
        for line in headers_text.split("\r\n")[1:]:
            if line.lower().startswith("content-length:"):
                try:
                    content_length = int(line.split(":", 1)[1].strip())
                except ValueError:
                    content_length = 0
        body = rest
        while len(body) < content_length:
            more = self._sock.recv(content_length - len(body))
            if not more:
                break
            body += more
        return head + b"\r\n\r\n" + body[:content_length]

    def options(self, uri: Optional[str] = None) -> RtspResponse:
        return self._send_request("OPTIONS", uri or self.request_uri)

    def describe(self, accept: str = "application/sdp") -> RtspDescribeResult:
        result = RtspDescribeResult(url=self.request_uri)
        resp = self._send_request("DESCRIBE", extra_headers={"Accept": accept})
        result.status = resp.status
        result.server = _header_get(resp.headers, "Server") or self.server
        result.content_type = _header_get(resp.headers, "Content-Type")
        result.content_base = _header_get(resp.headers, "Content-Base") or _header_get(
            resp.headers, "Content-Location"
        )
        if result.content_base:
            self.content_base = result.content_base
        if resp.status == 401:
            result.auth_required = True
            result.error = "authentication required"
            return result
        if not resp.ok:
            result.error = f"DESCRIBE {resp.status} {resp.reason}".strip()
            return result
        result.session_description = resp.body
        self.last_sdp = resp.body
        result.media = parse_sdp(resp.body)
        self.last_media = list(result.media)
        return result

    def _track_uri(self, control: str) -> str:
        control = str(control or "").strip()
        if not control:
            return self.request_uri
        if control.startswith("rtsp://") or control.startswith("rtsps://"):
            return control
        base = self.content_base or self.request_uri
        if not base.endswith("/"):
            # RFC 2326 relative resolution — keep path directory
            if "/" in base.rsplit("://", 1)[-1]:
                base = base.rsplit("/", 1)[0] + "/"
            else:
                base = base + "/"
        if control.startswith("/"):
            scheme = "rtsps" if self.use_tls else "rtsp"
            return f"{scheme}://{self.host}:{self.port}{control}"
        return base + control

    def setup(
        self,
        control: str = "",
        interleaved_channel: int = 0,
        client_ports: Tuple[int, int] = (5000, 5001),
        transport: str = "tcp",
    ) -> RtspResponse:
        uri = self._track_uri(control)
        if str(transport).lower() == "udp":
            transport_header = (
                f"RTP/AVP;unicast;client_port={client_ports[0]}-{client_ports[1]}"
            )
        else:
            ch0 = int(interleaved_channel)
            transport_header = f"RTP/AVP/TCP;unicast;interleaved={ch0}-{ch0 + 1}"
        resp = self._send_request("SETUP", uri, extra_headers={"Transport": transport_header})
        if resp.ok:
            self.transport = _header_get(resp.headers, "Transport") or transport_header
        return resp

    def play(self, range_header: str = "npt=0.000-") -> RtspResponse:
        uri = self.content_base.rstrip("/") if self.content_base else self.request_uri
        resp = self._send_request("PLAY", uri, extra_headers={"Range": range_header})
        self.playing = resp.ok
        return resp

    def teardown(self) -> RtspResponse:
        uri = self.content_base.rstrip("/") if self.content_base else self.request_uri
        resp = self._send_request("TEARDOWN", uri)
        self.session_id = ""
        self.playing = False
        return resp

    def drain_interleaved(self, max_bytes: int = 65536, wait: float = 2.0) -> bytes:
        """Read interleaved RTP/RTCP frames after PLAY (proves media path)."""
        if not self._sock:
            return b""
        old = self._sock.gettimeout()
        self._sock.settimeout(max(0.2, float(wait)))
        buf = b""
        try:
            while len(buf) < max_bytes:
                try:
                    chunk = self._sock.recv(min(4096, max_bytes - len(buf)))
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
        finally:
            try:
                self._sock.settimeout(old)
            except Exception:
                pass
        return buf

    def probe(self) -> Dict[str, object]:
        """OPTIONS + DESCRIBE summary without SETUP/PLAY."""
        info: Dict[str, object] = {
            "url": self.request_uri,
            "connected": self.connected,
            "options": list(self.last_options),
            "server": self.server,
            "auth_required": False,
            "media": [],
            "error": "",
        }
        if not self.connected and not self.connect():
            info["error"] = self.last_error or "connect failed"
            return info
        if not self.last_options:
            opt = self.options()
            public = _header_get(opt.headers, "Public") or _header_get(opt.headers, "Allow")
            if public:
                self.last_options = [m.strip() for m in public.split(",") if m.strip()]
            info["options"] = list(self.last_options)
            info["server"] = _header_get(opt.headers, "Server") or self.server
            if opt.status == 401:
                info["auth_required"] = True
        desc = self.describe()
        info["auth_required"] = bool(info["auth_required"] or desc.auth_required)
        info["server"] = desc.server or info["server"]
        info["media"] = [
            {
                "type": m.media_type,
                "control": m.control,
                "encoding": m.encoding,
                "rtpmap": m.rtpmap,
            }
            for m in desc.media
        ]
        if desc.error:
            info["error"] = desc.error
        return info

    def open_stream_tcp(self, prefer_video: bool = True) -> Dict[str, object]:
        """DESCRIBE → SETUP (interleaved) → PLAY → short drain."""
        out: Dict[str, object] = {
            "url": self.request_uri,
            "setup_ok": False,
            "play_ok": False,
            "bytes_drained": 0,
            "transport": "",
            "track": "",
            "error": "",
        }
        if not self.connected and not self.connect():
            out["error"] = self.last_error or "connect failed"
            return out
        desc = self.describe()
        if desc.error and not desc.media:
            out["error"] = desc.error
            return out
        track = ""
        for m in desc.media:
            if prefer_video and m.media_type == "video":
                track = m.control
                break
        if not track and desc.media:
            track = desc.media[0].control
        out["track"] = track
        setup = self.setup(track or "", transport="tcp")
        out["setup_ok"] = setup.ok
        out["transport"] = self.transport
        if not setup.ok:
            out["error"] = f"SETUP {setup.status} {setup.reason}".strip()
            return out
        play = self.play()
        out["play_ok"] = play.ok
        if not play.ok:
            out["error"] = f"PLAY {play.status} {play.reason}".strip()
            return out
        data = self.drain_interleaved(max_bytes=32768, wait=2.0)
        out["bytes_drained"] = len(data)
        return out


def probe_rtsp(
    host: str,
    port: int = RTSP_PORT,
    path: str = "/",
    username: str = "",
    password: str = "",
    timeout: float = 5.0,
    url: str = "",
) -> Dict[str, object]:
    client = RtspClient(
        host=host,
        port=port,
        path=path,
        username=username,
        password=password,
        timeout=timeout,
        url=url,
    )
    try:
        return client.probe()
    finally:
        client.close()
