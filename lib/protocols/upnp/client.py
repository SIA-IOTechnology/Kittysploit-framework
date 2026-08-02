#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""UPnP / SSDP client — discover, parse device description, invoke SOAP actions (IGD)."""

from __future__ import annotations

import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape


SSDP_PORT = 1900
SSDP_ADDR = "239.255.255.250"

WAN_SERVICE_HINTS = (
    "WANIPConnection",
    "WANPPPConnection",
    "WANCommonInterfaceConfig",
    "Layer3Forwarding",
)


def _local_tag(name: str) -> str:
    if "}" in name:
        return name.rsplit("}", 1)[-1]
    if ":" in name:
        return name.split(":")[-1]
    return name


def _msearch(st: str = "ssdp:all", mx: int = 2) -> bytes:
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"MX: {int(mx)}\r\n"
        f"ST: {st}\r\n"
        "\r\n"
    ).encode("utf-8")


def _parse_ssdp_headers(text: str) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        headers[key.strip().lower()] = val.strip()
    return headers


@dataclass
class UpnpService:
    service_type: str = ""
    service_id: str = ""
    control_url: str = ""
    scpd_url: str = ""
    event_sub_url: str = ""

    @property
    def is_wan(self) -> bool:
        st = self.service_type.upper()
        return any(h.upper() in st for h in WAN_SERVICE_HINTS)


@dataclass
class UpnpDevice:
    device_type: str = ""
    friendly_name: str = ""
    manufacturer: str = ""
    model_name: str = ""
    model_number: str = ""
    serial_number: str = ""
    udn: str = ""
    presentation_url: str = ""
    services: List[UpnpService] = field(default_factory=list)
    children: List["UpnpDevice"] = field(default_factory=list)

    def all_services(self) -> List[UpnpService]:
        out = list(self.services)
        for child in self.children:
            out.extend(child.all_services())
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_type": self.device_type,
            "friendly_name": self.friendly_name,
            "manufacturer": self.manufacturer,
            "model_name": self.model_name,
            "model_number": self.model_number,
            "serial_number": self.serial_number,
            "udn": self.udn,
            "presentation_url": self.presentation_url,
            "services": [
                {
                    "service_type": s.service_type,
                    "service_id": s.service_id,
                    "control_url": s.control_url,
                    "scpd_url": s.scpd_url,
                }
                for s in self.services
            ],
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class UpnpClient:
    """Session-oriented UPnP client (SSDP discover + description + SOAP)."""

    host: str
    port: int = SSDP_PORT
    timeout: float = 5.0
    location: str = ""
    server: str = ""
    st: str = ""
    usn: str = ""
    base_url: str = ""
    description_xml: str = ""
    root_device: Optional[UpnpDevice] = None
    last_error: str = ""
    _connected: bool = False

    @property
    def connected(self) -> bool:
        return bool(self._connected and (self.location or self.root_device))

    def _resolve_url(self, path: str) -> str:
        path = str(path or "").strip()
        if not path:
            return ""
        if path.startswith("http://") or path.startswith("https://"):
            return path
        base = self.base_url or self.location
        if not base:
            return path
        return urllib.parse.urljoin(base if base.endswith("/") else base + "/", path.lstrip("/"))

    def discover(self, *, st: str = "ssdp:all", multicast: bool = False) -> bool:
        """SSDP M-SEARCH (unicast to host by default). Sets location/headers."""
        self.last_error = ""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self.timeout)
            target = (SSDP_ADDR, SSDP_PORT) if multicast else (self.host, int(self.port))
            sock.sendto(_msearch(st=st), target)
            deadline_responses = 1 if not multicast else 8
            for _ in range(deadline_responses):
                try:
                    data, addr = sock.recvfrom(8192)
                except socket.timeout:
                    break
                text = data.decode("utf-8", errors="replace")
                headers = _parse_ssdp_headers(text)
                location = headers.get("location") or ""
                if not location:
                    continue
                # Prefer replies from target host when multicast
                if multicast and self.host and addr[0] not in (self.host, "127.0.0.1"):
                    # Keep first valid if host filter empty later
                    if not self.location:
                        self.location = location
                        self.server = headers.get("server", "")
                        self.st = headers.get("st", "")
                        self.usn = headers.get("usn", "")
                    continue
                self.location = location
                self.server = headers.get("server", "")
                self.st = headers.get("st", "")
                self.usn = headers.get("usn", "")
                self.host = self.host or addr[0]
                break
            if not self.location:
                self.last_error = "no SSDP response / LOCATION"
                self._connected = False
                return False
            return True
        except Exception as exc:
            self.last_error = str(exc)
            self._connected = False
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _http_get(self, url: str) -> Tuple[int, str]:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "KittySploit-UPnP/1.0", "Accept": "text/xml, application/xml, */*"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return int(resp.status), resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            self.last_error = f"HTTP {exc.code}"
            return int(exc.code), body
        except Exception as exc:
            self.last_error = str(exc)
            return 0, ""

    def fetch_description(self, location: str = "") -> bool:
        url = (location or self.location or "").strip()
        if not url:
            self.last_error = "no LOCATION URL"
            return False
        code, body = self._http_get(url)
        if code != 200 or not body:
            self.last_error = self.last_error or f"description fetch failed ({code})"
            return False
        self.location = url
        self.description_xml = body
        parts = urllib.parse.urlsplit(url)
        self.base_url = f"{parts.scheme}://{parts.netloc}/"
        self.root_device = self._parse_device_tree(body)
        self._connected = self.root_device is not None
        if not self._connected:
            self.last_error = "failed to parse device description"
        return self._connected

    def _parse_device_tree(self, xml_text: str) -> Optional[UpnpDevice]:
        # Lightweight regex/XML hybrid — avoid requiring lxml
        try:
            import xml.etree.ElementTree as ET

            root = ET.fromstring(xml_text)
        except Exception as exc:
            self.last_error = f"XML parse error: {exc}"
            return None

        def text(el, *names: str) -> str:
            if el is None:
                return ""
            for child in list(el):
                if _local_tag(child.tag) in names:
                    return (child.text or "").strip()
            return ""

        def parse_device(el) -> UpnpDevice:
            device = UpnpDevice(
                device_type=text(el, "deviceType"),
                friendly_name=text(el, "friendlyName"),
                manufacturer=text(el, "manufacturer"),
                model_name=text(el, "modelName"),
                model_number=text(el, "modelNumber"),
                serial_number=text(el, "serialNumber"),
                udn=text(el, "UDN"),
                presentation_url=text(el, "presentationURL"),
            )
            for child in list(el):
                tag = _local_tag(child.tag)
                if tag == "serviceList":
                    for svc_el in list(child):
                        if _local_tag(svc_el.tag) != "service":
                            continue
                        service = UpnpService(
                            service_type=text(svc_el, "serviceType"),
                            service_id=text(svc_el, "serviceId"),
                            control_url=self._resolve_url(text(svc_el, "controlURL")),
                            scpd_url=self._resolve_url(text(svc_el, "SCPDURL")),
                            event_sub_url=self._resolve_url(text(svc_el, "eventSubURL")),
                        )
                        device.services.append(service)
                elif tag == "deviceList":
                    for nested in list(child):
                        if _local_tag(nested.tag) == "device":
                            device.children.append(parse_device(nested))
            return device

        device_el = None
        for el in root.iter():
            if _local_tag(el.tag) == "device":
                device_el = el
                break
        if device_el is None:
            return None
        return parse_device(device_el)

    def connect(self, *, location: str = "", st: str = "ssdp:all") -> bool:
        """Discover (unless location given) and fetch/parse description."""
        if location:
            self.location = location
        elif not self.location:
            if not self.discover(st=st, multicast=False):
                # Fallback multicast filter
                if not self.discover(st=st, multicast=True):
                    return False
        return self.fetch_description(self.location)

    def close(self) -> None:
        self._connected = False

    def list_services(self) -> List[UpnpService]:
        if not self.root_device:
            return []
        return self.root_device.all_services()

    def find_wan_service(self) -> Optional[UpnpService]:
        for svc in self.list_services():
            if "WANIPConnection" in svc.service_type or "WANPPPConnection" in svc.service_type:
                return svc
        for svc in self.list_services():
            if svc.is_wan:
                return svc
        return None

    def soap_action(
        self,
        service: UpnpService,
        action: str,
        args: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str]:
        """Invoke a UPnP SOAP action on a service controlURL."""
        if not service.control_url:
            self.last_error = "empty controlURL"
            return 0, ""
        args = args or {}
        args_xml = "".join(
            f"<{escape(k)}>{escape(str(v))}</{escape(k)}>" for k, v in args.items()
        )
        body = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            "<s:Body>"
            f'<u:{escape(action)} xmlns:u="{escape(service.service_type)}">'
            f"{args_xml}"
            f"</u:{escape(action)}>"
            "</s:Body></s:Envelope>"
        )
        headers = {
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{service.service_type}#{action}"',
            "User-Agent": "KittySploit-UPnP/1.0",
        }
        req = urllib.request.Request(
            service.control_url,
            data=body.encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return int(resp.status), resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body_err = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            self.last_error = f"SOAP HTTP {exc.code}: {body_err[:200]}"
            return int(exc.code), body_err
        except Exception as exc:
            self.last_error = str(exc)
            return 0, ""

    @staticmethod
    def _soap_values(body: str) -> Dict[str, str]:
        values: Dict[str, str] = {}
        for m in re.finditer(r"<([A-Za-z0-9_:]+)>([^<]*)</\1>", body):
            key = _local_tag(m.group(1))
            if key.lower().startswith("u:"):
                continue
            values[key] = m.group(2).strip()
        return values

    def get_external_ip(self, service: Optional[UpnpService] = None) -> str:
        svc = service or self.find_wan_service()
        if not svc:
            self.last_error = "no WANIP/WANPPP service"
            return ""
        code, body = self.soap_action(svc, "GetExternalIPAddress")
        if code != 200:
            return ""
        vals = self._soap_values(body)
        return vals.get("NewExternalIPAddress") or vals.get("ExternalIPAddress") or ""

    def get_status_info(self, service: Optional[UpnpService] = None) -> Dict[str, str]:
        svc = service or self.find_wan_service()
        if not svc:
            return {}
        code, body = self.soap_action(svc, "GetStatusInfo")
        if code != 200:
            return {}
        return self._soap_values(body)

    def get_port_mappings(
        self,
        service: Optional[UpnpService] = None,
        *,
        max_entries: int = 64,
    ) -> List[Dict[str, str]]:
        """Enumerate IGD port mappings via GetGenericPortMappingEntry."""
        svc = service or self.find_wan_service()
        if not svc:
            self.last_error = "no WANIP/WANPPP service"
            return []
        mappings: List[Dict[str, str]] = []
        for index in range(max(1, int(max_entries))):
            code, body = self.soap_action(
                svc,
                "GetGenericPortMappingEntry",
                {"NewPortMappingIndex": str(index)},
            )
            if code != 200:
                # 500 / 713 typically means end of list
                break
            vals = self._soap_values(body)
            if not vals:
                break
            mappings.append(vals)
        return mappings

    def inventory(self) -> Dict[str, Any]:
        device = self.root_device.to_dict() if self.root_device else {}
        services = [
            {
                "service_type": s.service_type,
                "control_url": s.control_url,
                "is_wan": s.is_wan,
            }
            for s in self.list_services()
        ]
        return {
            "host": self.host,
            "port": self.port,
            "location": self.location,
            "server": self.server,
            "st": self.st,
            "usn": self.usn,
            "device": device,
            "services": services,
        }
