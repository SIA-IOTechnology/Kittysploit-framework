# -*- coding: utf-8 -*-

from __future__ import annotations

import base64
import re
import uuid
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict


def _stream_key(ip_src: str, port_src: int, ip_dst: str, port_dst: int) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    """Normalize (client, server) so both directions map to same stream."""
    a = (str(ip_src), int(port_src))
    b = (str(ip_dst), int(port_dst))
    return (a, b) if a < b else (b, a)


def _decode(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="replace")
    return str(v)


def _content_from_pkt(pkt) -> bytes:
    if pkt.haslayer("Raw"):
        return bytes(pkt["Raw"].load)
    return b""


def _headers_from_scapy(pkt) -> Dict[str, str]:
    """Extract a minimal headers dict from scapy HTTP packet."""
    out: Dict[str, str] = {}
    for name in ("HTTP 1", "HTTPRequest", "HTTPResponse"):
        layer = pkt.getlayer(name)
        if layer is None:
            continue
        for f in getattr(layer, "fields_desc", []):
            n = f.name
            if n.startswith("Http_") or n in ("Method", "Path", "Host", "Http_Version", "Status_Code", "Reason_Phrase"):
                continue
            val = layer.getfieldval(n)
            if val is None:
                continue
            h = n.replace("_", "-").title()
            out[h] = _decode(val)
        break
    return out


# -----------------------------------------------------------------------------
# Raw HTTP fallback: parse TCP payloads when Scapy HTTP layers are not present
# (e.g. non-standard ports, or scapy not dissecting)
# -----------------------------------------------------------------------------

# Request line: match anywhere in blob (no ^) for fragmented / prefixed data
_REQ_LINE = re.compile(rb"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP/[\d.]+\r?\n", re.I)
_HOST = re.compile(rb"\r?\nhost:\s*([^\r\n]+)", re.I)
_STATUS = re.compile(rb"HTTP/[\d.]+\s+(\d{3})\s+([^\r\n]*)\r?\n")


def _parse_http_raw_stream(blob: bytes, server_port: int) -> Optional[Dict[str, Any]]:
    """Parse concatenated TCP payload of one stream; extract first HTTP req+resp."""
    if not blob or len(blob) < 10:
        return None
    req_m = _REQ_LINE.search(blob)
    if not req_m:
        return None
    method = req_m.group(1).decode("utf-8", errors="replace").strip().upper()
    path = req_m.group(2).decode("utf-8", errors="replace").strip()
    if not path:
        path = "/"
    host_m = _HOST.search(blob, req_m.end())
    host = host_m.group(1).decode("utf-8", errors="replace").strip() if host_m else ""
    # Response status: first "HTTP/1.x DDD" *after* the request line
    request_line_end = blob.find(b"\n", req_m.start()) + 1
    rest = blob[request_line_end:] if request_line_end else blob
    status_m = _STATUS.search(rest)
    status_code = int(status_m.group(1)) if status_m else None
    reason = status_m.group(2).decode("utf-8", errors="replace").strip() if status_m else ""

    scheme = "https" if server_port in (443, 8443) else "http"
    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        url = f"{scheme}://{host}{path}" if host else f"{scheme}://unknown{path}"

    flow = {
        "id": str(uuid.uuid4()),
        "method": method,
        "scheme": scheme,
        "host": host,
        "path": path,
        "url": url,
        "status_code": status_code,
        "duration_ms": None,
        "duration": None,
        "response_size": 0,
        "source": "pcap",
        "technologies": {},
        "fingerprint": {},
        "module_suggestions": [],
        "endpoints": {},
        "discovered_endpoints": [],
        "ws_messages": [],
        "intercepted": False,
        "request": {"headers": {"Host": host} if host else {}, "content_bs64": "", "content_length": 0},
        "response": {"headers": {}, "content_bs64": "", "content_length": 0, "reason": reason},
        "timestamp_start": 0,
    }
    return flow


def _get_ip_layer(pkt):
    """Return (src, dst) from IP or IPv6 layer."""
    if pkt.haslayer("IP"):
        L = pkt["IP"]
        return (str(L.src), str(L.dst))
    if pkt.haslayer("IPv6"):
        L = pkt["IPv6"]
        return (str(L.src), str(L.dst))
    return (None, None)


def _extract_flows_raw(path: str) -> List[Dict[str, Any]]:
    """Fallback: no HTTP layers, parse Raw TCP payloads. Works on any port. Supports IPv4/IPv6."""
    from scapy.all import rdpcap, TCP, IP, Raw

    pkts = rdpcap(path)
    streams: Dict[Tuple[Tuple[str, int], Tuple[str, int]], List[Tuple[float, bytes]]] = defaultdict(list)
    for pkt in pkts:
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            continue
        src, dst = _get_ip_layer(pkt)
        if src is None or dst is None:
            continue
        tcp = pkt[TCP]
        ts = float(getattr(pkt, "time", 0) or 0)
        key = _stream_key(src, tcp.sport, dst, tcp.dport)
        payload = bytes(pkt[Raw].load)
        streams[key].append((ts, payload))

    flows: List[Dict[str, Any]] = []
    for key, items in streams.items():
        items.sort(key=lambda x: x[0])
        blob = b"".join(p[1] for p in items)
        p1, p2 = key[0][1], key[1][1]
        server_port = p1 if p1 in (80, 443, 8080, 8000, 8443, 8888) else (p2 if p2 in (80, 443, 8080, 8000, 8443, 8888) else 80)
        f = _parse_http_raw_stream(blob, server_port)
        if f:
            ts0 = items[0][0]
            f["timestamp_start"] = ts0
            flows.append(f)

    # Single-packet fallback: if no flows from streams, try each Raw packet alone
    if not flows:
        for pkt in pkts:
            if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                continue
            src, dst = _get_ip_layer(pkt)
            if src is None:
                continue
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            sp = sport if sport in (80, 443, 8080, 8000, 8443, 8888) else (dport if dport in (80, 443, 8080, 8000, 8443, 8888) else 80)
            blob = bytes(pkt[Raw].load)
            f = _parse_http_raw_stream(blob, sp)
            if f:
                f["timestamp_start"] = float(getattr(pkt, "time", 0) or 0)
                flows.append(f)
    return flows


# -----------------------------------------------------------------------------
# Scapy HTTP layers (TCPSession)
# -----------------------------------------------------------------------------


def _ensure_http_layer() -> bool:
    try:
        from scapy.layers.http import HTTPRequest, HTTPResponse  # noqa: F401
        return True
    except Exception:
        pass
    try:
        from scapy.loader import load_layer
        load_layer("http")
        return True
    except Exception:
        return False


def _extract_flows_scapy_http(path: str) -> List[Dict[str, Any]]:
    """Use Scapy HTTPRequest/HTTPResponse per packet (rdpcap, no TCPSession)."""
    from scapy.all import rdpcap, TCP, IP, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
    try:
        from scapy.loader import load_layer
        load_layer("http")
    except Exception:
        pass

    pkts = rdpcap(path)
    streams: Dict[Tuple[Tuple[str, int], Tuple[str, int]], List[Tuple[float, str, Any]]] = defaultdict(list)

    for pkt in pkts:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        ts = float(getattr(pkt, "time", 0) or 0)
        key = _stream_key(ip.src, tcp.sport, ip.dst, tcp.dport)
        if pkt.haslayer(HTTPRequest):
            streams[key].append((ts, "request", pkt))
        elif pkt.haslayer(HTTPResponse):
            streams[key].append((ts, "response", pkt))

    flows: List[Dict[str, Any]] = []
    for key, items in streams.items():
        items.sort(key=lambda x: x[0])
        reqs = [(t, p) for t, typ, p in items if typ == "request"]
        resps = [(t, p) for t, typ, p in items if typ == "response"]
        for i in range(max(len(reqs), len(resps)) if (reqs or resps) else 0):
            p_req = reqs[i][1] if i < len(reqs) else None
            p_resp = resps[i][1] if i < len(resps) else None
            t_req = reqs[i][0] if i < len(reqs) else 0.0
            t_resp = resps[i][0] if i < len(resps) else t_req
            if p_req is None:
                continue
            req_layer = p_req.getlayer(HTTPRequest)
            if req_layer is None:
                continue
            method = _decode(getattr(req_layer, "Method", None) or req_layer.getfieldval("Method") or b"GET").strip() or "GET"
            path = _decode(getattr(req_layer, "Path", None) or req_layer.getfieldval("Path") or b"/").strip() or "/"
            host = _decode(getattr(req_layer, "Host", None) or req_layer.getfieldval("Host") or b"").strip()
            scheme = "https" if (key[0][1] == 443 or key[1][1] == 443) else "http"
            url = f"{scheme}://{host}{path}" if host else f"{scheme}://unknown{path}"
            status_code = None
            reason = ""
            req_content = _content_from_pkt(p_req)
            resp_content = b""
            resp_headers = {}
            if p_resp is not None:
                resp_layer = p_resp.getlayer(HTTPResponse)
                if resp_layer is not None:
                    try:
                        sc = getattr(resp_layer, "Status_Code", None) or resp_layer.getfieldval("Status_Code")
                        if sc is not None:
                            status_code = int(_decode(sc).strip())
                    except (TypeError, ValueError):
                        pass
                    reason = _decode(getattr(resp_layer, "Reason_Phrase", None) or resp_layer.getfieldval("Reason_Phrase") or b"")
                    resp_content = _content_from_pkt(p_resp)
                    resp_headers = _headers_from_scapy(p_resp)
            response_size = len(resp_content)
            duration_ms = int((t_resp - t_req) * 1000) if t_resp >= t_req else None
            req_headers = _headers_from_scapy(p_req)
            if host and "Host" not in req_headers:
                req_headers["Host"] = host

            flow = {
                "id": str(uuid.uuid4()),
                "method": method,
                "scheme": scheme,
                "host": host,
                "path": path,
                "url": url,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "duration": (t_resp - t_req) if t_resp >= t_req else None,
                "response_size": response_size,
                "source": "pcap",
                "technologies": {},
                "fingerprint": {},
                "module_suggestions": [],
                "endpoints": {},
                "discovered_endpoints": [],
                "ws_messages": [],
                "intercepted": False,
                "request": {
                    "headers": req_headers,
                    "content_bs64": base64.b64encode(req_content).decode("utf-8"),
                    "content_length": len(req_content),
                },
                "response": {
                    "headers": resp_headers,
                    "content_bs64": base64.b64encode(resp_content).decode("utf-8"),
                    "content_length": len(resp_content),
                    "reason": reason,
                },
                "timestamp_start": t_req,
            }
            flows.append(flow)
    return flows


def _check_scapy() -> None:
    """Ensure scapy is available; raise RuntimeError with install hint if not."""
    try:
        from scapy.all import rdpcap, TCP, IP, Raw  # noqa: F401
    except ImportError as e:
        raise RuntimeError(
            "Scapy is required for PCAP import. Install it with: pip install scapy"
        ) from e


def extract_flows_from_pcap(path: str) -> List[Dict[str, Any]]:
    """
    Parse a PCAP file and return flow-like dicts (HTTP/HTTPS).
    Tries Scapy HTTP layers first; falls back to raw TCP parsing if none found.
    """
    _check_scapy()
    flows: List[Dict[str, Any]] = []
    if _ensure_http_layer():
        try:
            flows = _extract_flows_scapy_http(path)
        except Exception:
            pass
    if not flows:
        flows = _extract_flows_raw(path)
    return flows
