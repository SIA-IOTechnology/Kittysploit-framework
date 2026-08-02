#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal ONVIF SOAP helpers (Device + Media + PTZ + Events) over HTTP — stdlib only."""

from __future__ import annotations

import base64
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape


DEFAULT_DEVICE_PATHS = (
    "/onvif/device_service",
    "/onvif/device",
    "/onvif/Device",
    "/device_service",
)


@dataclass
class OnvifDeviceInfo:
    manufacturer: str = ""
    model: str = ""
    firmware: str = ""
    serial: str = ""
    hardware: str = ""
    raw: str = ""


@dataclass
class OnvifClient:
    host: str
    port: int = 80
    username: str = ""
    password: str = ""
    use_https: bool = False
    timeout: float = 8.0
    device_path: str = "/onvif/device_service"
    media_xaddr: str = ""
    ptz_xaddr: str = ""
    events_xaddr: str = ""
    last_error: str = ""
    _connected: bool = False

    @property
    def connected(self) -> bool:
        return bool(self._connected and self.host)

    def _base(self) -> str:
        scheme = "https" if self.use_https else "http"
        return f"{scheme}://{self.host}:{int(self.port)}"

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self._base() + path

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/soap+xml; charset=utf-8",
            "Accept": "application/soap+xml, application/xml, text/xml, */*",
            "User-Agent": "KittySploit-ONVIF/1.0",
        }
        if self.username:
            token = base64.b64encode(
                f"{self.username}:{self.password}".encode("utf-8")
            ).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
        return headers

    def _soap(self, body_inner: str, action: str = "") -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:tds="http://www.onvif.org/ver10/device/wsdl" '
            'xmlns:trt="http://www.onvif.org/ver10/media/wsdl" '
            'xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" '
            'xmlns:tev="http://www.onvif.org/ver10/events/wsdl" '
            'xmlns:tt="http://www.onvif.org/ver10/schema" '
            'xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2">'
            f"<s:Body>{body_inner}</s:Body></s:Envelope>"
        )

    def request(self, path: str, body_inner: str, action: str = "") -> Tuple[int, str]:
        url = self._url(path)
        data = self._soap(body_inner, action).encode("utf-8")
        headers = self._headers()
        if action:
            headers["SOAPAction"] = f'"{action}"'
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return int(resp.status), resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            self.last_error = f"HTTP {exc.code}: {body[:200]}"
            return int(exc.code), body
        except Exception as exc:
            self.last_error = str(exc)
            return 0, ""

    @staticmethod
    def _grab(body: str, *tags: str) -> str:
        for tag in tags:
            m = re.search(rf"<{tag}[^>]*>([^<]+)</{tag}>", body, re.I)
            if m:
                return m.group(1).strip()
        return ""

    @staticmethod
    def _xaddrs(body: str) -> Dict[str, str]:
        """Extract service XAddrs keyed by service hint (media/ptz/events/device)."""
        found: Dict[str, str] = {}
        for m in re.finditer(
            r"<(?:tds|tt):(\w+)[^>]*>\s*<(?:tds|tt):XAddr>([^<]+)</(?:tds|tt):XAddr>",
            body,
            re.I | re.S,
        ):
            name = m.group(1).lower()
            found[name] = m.group(2).strip()
        # Fallback: any XAddr containing service keyword
        for key, needle in (
            ("media", "media"),
            ("ptz", "ptz"),
            ("events", "event"),
            ("device", "device"),
        ):
            if key in found:
                continue
            m = re.search(
                rf"<(?:tt|tds):XAddr>([^<]*{needle}[^<]*)</(?:tt|tds):XAddr>",
                body,
                re.I,
            )
            if m:
                found[key] = m.group(1).strip()
        return found

    def discover_device_service(self) -> bool:
        for path in DEFAULT_DEVICE_PATHS:
            code, body = self.request(
                path,
                "<tds:GetDeviceInformation/>",
                "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
            )
            if code == 200 and ("Manufacturer" in body or "GetDeviceInformationResponse" in body):
                self.device_path = path
                self._connected = True
                return True
        self._connected = False
        return False

    def connect(self) -> bool:
        """Discover device service and refresh capabilities XAddrs."""
        if not self.discover_device_service():
            return False
        self.get_capabilities()
        return True

    def close(self) -> None:
        self._connected = False

    def get_device_information(self) -> OnvifDeviceInfo:
        code, body = self.request(
            self.device_path,
            "<tds:GetDeviceInformation/>",
            "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
        )
        info = OnvifDeviceInfo(raw=body)
        if code == 200:
            info.manufacturer = self._grab(body, "tds:Manufacturer", "Manufacturer")
            info.model = self._grab(body, "tds:Model", "Model")
            info.firmware = self._grab(body, "tds:FirmwareVersion", "FirmwareVersion")
            info.serial = self._grab(body, "tds:SerialNumber", "SerialNumber")
            info.hardware = self._grab(body, "tds:HardwareId", "HardwareId")
        return info

    def get_capabilities(self) -> str:
        _code, body = self.request(
            self.device_path,
            "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>",
            "http://www.onvif.org/ver10/device/wsdl/GetCapabilities",
        )
        xaddrs = self._xaddrs(body)
        if xaddrs.get("media"):
            self.media_xaddr = xaddrs["media"]
        if xaddrs.get("ptz"):
            self.ptz_xaddr = xaddrs["ptz"]
        if xaddrs.get("events"):
            self.events_xaddr = xaddrs["events"]
        # Legacy fallbacks
        if not self.media_xaddr:
            m = re.search(r"<tt:XAddr>([^<]*media[^<]*)</tt:XAddr>", body, re.I)
            if not m:
                m = re.search(r"<tds:XAddr>([^<]*media[^<]*)</tds:XAddr>", body, re.I)
            if m:
                self.media_xaddr = m.group(1).strip()
        return body

    def _media_path(self) -> str:
        return self.media_xaddr or "/onvif/media_service"

    def _ptz_path(self) -> str:
        return self.ptz_xaddr or "/onvif/ptz_service"

    def _events_path(self) -> str:
        return self.events_xaddr or "/onvif/events_service"

    def get_profiles(self) -> List[str]:
        _code, body = self.request(
            self._media_path(),
            "<trt:GetProfiles/>",
            "http://www.onvif.org/ver10/media/wsdl/GetProfiles",
        )
        return re.findall(r'token="([^"]+)"', body)

    def get_profiles_detail(self) -> List[Dict[str, Any]]:
        _code, body = self.request(
            self._media_path(),
            "<trt:GetProfiles/>",
            "http://www.onvif.org/ver10/media/wsdl/GetProfiles",
        )
        details: List[Dict[str, Any]] = []
        for m in re.finditer(
            r'<(?:trt:)?Profiles\b[^>]*token="([^"]+)"[^>]*(?:name="([^"]*)")?',
            body,
            re.I,
        ):
            details.append({"token": m.group(1), "name": m.group(2) or ""})
        if not details:
            for token in re.findall(r'token="([^"]+)"', body):
                details.append({"token": token, "name": ""})
        return details

    def get_snapshot_uri(self, profile_token: str) -> str:
        inner = (
            "<trt:GetSnapshotUri>"
            f"<trt:ProfileToken>{escape(profile_token)}</trt:ProfileToken>"
            "</trt:GetSnapshotUri>"
        )
        _code, body = self.request(
            self._media_path(),
            inner,
            "http://www.onvif.org/ver10/media/wsdl/GetSnapshotUri",
        )
        return self._grab(body, "tt:Uri", "trt:Uri")

    def get_stream_uri(self, profile_token: str, protocol: str = "RTSP") -> str:
        """Resolve RTSP (or HTTP) stream URI for a media profile."""
        proto = escape(str(protocol or "RTSP"))
        inner = (
            "<trt:GetStreamUri>"
            "<trt:StreamSetup>"
            "<tt:Stream>RTP-Unicast</tt:Stream>"
            f"<tt:Transport><tt:Protocol>{proto}</tt:Protocol></tt:Transport>"
            "</trt:StreamSetup>"
            f"<trt:ProfileToken>{escape(profile_token)}</trt:ProfileToken>"
            "</trt:GetStreamUri>"
        )
        _code, body = self.request(
            self._media_path(),
            inner,
            "http://www.onvif.org/ver10/media/wsdl/GetStreamUri",
        )
        return self._grab(body, "tt:Uri", "trt:Uri")

    def get_ptz_status(self, profile_token: str) -> Dict[str, Any]:
        inner = (
            "<tptz:GetStatus>"
            f"<tptz:ProfileToken>{escape(profile_token)}</tptz:ProfileToken>"
            "</tptz:GetStatus>"
        )
        code, body = self.request(
            self._ptz_path(),
            inner,
            "http://www.onvif.org/ver20/ptz/wsdl/GetStatus",
        )
        result: Dict[str, Any] = {"ok": code == 200, "raw": body, "pan": "", "tilt": "", "zoom": ""}
        if code != 200:
            return result
        # Position/PanTilt attributes vary by vendor
        m = re.search(
            r'<(?:tt:)?PanTilt[^>]*x="([^"]+)"[^>]*y="([^"]+)"',
            body,
            re.I,
        )
        if m:
            result["pan"], result["tilt"] = m.group(1), m.group(2)
        z = re.search(r'<(?:tt:)?Zoom[^>]*x="([^"]+)"', body, re.I)
        if z:
            result["zoom"] = z.group(1)
        result["moving"] = "Moving" in body or "moveStatus" in body.lower()
        return result

    def ptz_continuous_move(
        self,
        profile_token: str,
        *,
        pan: float = 0.0,
        tilt: float = 0.0,
        zoom: float = 0.0,
    ) -> bool:
        inner = (
            "<tptz:ContinuousMove>"
            f"<tptz:ProfileToken>{escape(profile_token)}</tptz:ProfileToken>"
            "<tptz:Velocity>"
            f'<tt:PanTilt x="{float(pan)}" y="{float(tilt)}"/>'
            f'<tt:Zoom x="{float(zoom)}"/>'
            "</tptz:Velocity>"
            "</tptz:ContinuousMove>"
        )
        code, _body = self.request(
            self._ptz_path(),
            inner,
            "http://www.onvif.org/ver20/ptz/wsdl/ContinuousMove",
        )
        return code == 200

    def ptz_stop(self, profile_token: str) -> bool:
        inner = (
            "<tptz:Stop>"
            f"<tptz:ProfileToken>{escape(profile_token)}</tptz:ProfileToken>"
            "<tptz:PanTilt>true</tptz:PanTilt>"
            "<tptz:Zoom>true</tptz:Zoom>"
            "</tptz:Stop>"
        )
        code, _body = self.request(
            self._ptz_path(),
            inner,
            "http://www.onvif.org/ver20/ptz/wsdl/Stop",
        )
        return code == 200

    def get_event_properties(self) -> Dict[str, Any]:
        code, body = self.request(
            self._events_path(),
            "<tev:GetEventProperties/>",
            "http://www.onvif.org/ver10/events/wsdl/GetEventProperties",
        )
        topics = re.findall(r"<[^>]*Topic[^>]*>([^<]+)</[^>]*Topic[^>]*>", body, re.I)
        if not topics:
            topics = re.findall(r'topic="([^"]+)"', body, re.I)
        return {
            "ok": code == 200,
            "topics": topics[:50],
            "bytes": len(body),
            "raw_preview": body[:500],
        }

    def download_uri(self, uri: str) -> bytes:
        headers = self._headers()
        headers.pop("Content-Type", None)
        req = urllib.request.Request(uri, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read()
