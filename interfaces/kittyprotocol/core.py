#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import math
import os
import re
import socket
import threading
import time
import json
import uuid
import ipaddress
from collections import Counter
from datetime import datetime
from io import BytesIO
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from kittysploit import print_info, print_status, print_success, print_table, print_warning

from . import protocol_intel
from .compare_engine import compare_summaries
from .investigation_store import InvestigationStore
from .payload_index import PayloadIndex
from .playbooks import get_playbook, modules_for_observation
from .provenance import build_provenance


class KittyProtocolAnalyzer:
    """Max packets returned in `GET /api/flows/<id>` (the rest via `/packets`)."""

    REPLAY_PACKETS_CLIENT_CAP = 200

    CREDENTIAL_FIELD_RE = re.compile(
        r"(user(name)?|login|pass(word|wd)?|token|bearer|api[_-]?key|secret|session(id)?|authorization|cookie)",
        re.I,
    )
    CLEAR_VALUE_RE = re.compile(
        r"(?i)(basic\s+[a-z0-9+/=]{8,}|bearer\s+[a-z0-9._\-+/=]{10,}|[a-z0-9._%+\-]+:[^:\s]{3,}|[a-f0-9]{24,}|[A-Za-z0-9_\-]{20,})"
    )
    AUTH_HINT_RE = re.compile(r"(auth|login|session|token|key|nonce|cookie|bearer)", re.I)
    NONCE_HINT_RE = re.compile(r"(nonce|random|challenge|salt|timestamp|ts|cnonce|request_id|uuid)", re.I)
    SENSITIVE_ENDPOINT_RE = re.compile(r"(login|admin|token|auth|config|debug|exec|command|shell|upload|delete|reset)", re.I)
    TEXT_SPLIT_RE = re.compile(r"[;&,\s]+")
    HTTP_REQ_LINE_RE = re.compile(rb"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP/[\d.]+\r?\n", re.I)
    HTTP_HOST_RE = re.compile(rb"\r?\nhost:\s*([^\r\n]+)", re.I)
    HTTP_STATUS_RE = re.compile(rb"HTTP/[\d.]+\s+(\d{3})\s+([^\r\n]*)\r?\n")
    URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
    EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
    IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
    DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")
    HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")

    def __init__(
        self,
        sensitive_keywords: Optional[List[str]] = None,
        live_update_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        recordings_dir: Optional[str] = None,
    ):
        self.sensitive_keywords = sensitive_keywords or [
            "login", "auth", "token", "password", "passwd", "apikey",
            "secret", "admin", "debug", "config", "cmd", "exec", "upload", "delete",
        ]
        self._lock = threading.RLock()
        self._live_thread: Optional[threading.Thread] = None
        self._live_stop = threading.Event()
        self._live_state: Dict[str, Any] = {
            "running": False,
            "interface": "",
            "sniff_interface": "",
            "capture_note": "",
            "display_filter": "",
            "protocol_filter": [],
            "started_at": None,
            "observed_packets": 0,
            "processed_packets": 0,
            "packet_errors": 0,
            "include_raw": False,
            "max_packets": 0,
            "error": "",
            "warning": "",
            "capture_backend": "scapy",
        }
        self._live_flows: Dict[str, Dict[str, Any]] = {}
        self._analysis_cache: Dict[str, Dict[str, Any]] = {}
        self._last_result: Dict[str, Any] = {}
        self._last_recording_bundle: Dict[str, Any] = {}
        self._live_update_callback = live_update_callback
        self._last_live_emit_ts = 0.0
        self._recordings_dir = os.path.abspath(recordings_dir or os.path.join(os.path.dirname(__file__), "recordings"))
        os.makedirs(self._recordings_dir, exist_ok=True)
        self.investigation = InvestigationStore()
        self._payload_index: Optional[PayloadIndex] = None
        self._session_id: str = ""
        self._live_session_id: str = ""
        self._last_source_pcap: str = ""
        self._decryption_config: Dict[str, Any] = {
            "tls_keylog_path": "",
            "persist_secrets": False,
            "updated_at": "",
        }

    def health(self) -> Dict[str, Any]:
        return {
            "app": "kittyprotocol",
            "backend": "scapy",
            "scapy_available": self._can_import_scapy(),
            "live_capture": self.get_live_status(),
            "decryption": self.get_decryption_config(),
        }

    def get_decryption_config(self) -> Dict[str, Any]:
        with self._lock:
            cfg = dict(self._decryption_config)
        keylog = str(cfg.get("tls_keylog_path") or "").strip()
        cfg["tls_keylog_exists"] = bool(keylog and os.path.isfile(keylog))
        return cfg

    def set_decryption_config(self, tls_keylog_path: Optional[str] = None, persist_secrets: Optional[bool] = None) -> Dict[str, Any]:
        with self._lock:
            cfg = dict(self._decryption_config)
            if tls_keylog_path is not None:
                path = os.path.abspath(str(tls_keylog_path or "").strip()) if str(tls_keylog_path or "").strip() else ""
                if path and not os.path.isfile(path):
                    return {"error": f"TLS keylog file not found: {path}"}
                cfg["tls_keylog_path"] = path
            if persist_secrets is not None:
                cfg["persist_secrets"] = bool(persist_secrets)
            cfg["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            self._decryption_config = cfg
        return {"status": "updated", "config": self.get_decryption_config()}

    def clear_decryption_config(self) -> Dict[str, Any]:
        with self._lock:
            self._decryption_config = {
                "tls_keylog_path": "",
                "persist_secrets": False,
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
        return {"status": "cleared", "config": self.get_decryption_config()}

    def get_decryption_status(self, flows: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        selected = list(flows if flows is not None else (self._last_result.get("flows", []) or []))
        cfg = self.get_decryption_config()
        keylog = str(cfg.get("tls_keylog_path") or "").strip()
        has_keylog = bool(keylog and os.path.isfile(keylog))
        keylog_size = os.path.getsize(keylog) if has_keylog else 0
        keylog_mtime = (
            time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(os.path.getmtime(keylog)))
            if has_keylog
            else ""
        )
        tls_flows = [flow for flow in selected if str(flow.get("protocol", "")).upper() in {"TLS", "HTTPS", "HTTP2"}]
        rows: List[Dict[str, Any]] = []
        decryptable = 0
        for flow in tls_flows[:300]:
            fid = str(flow.get("id") or "")
            detail = self._analysis_cache.get(fid, {})
            pkts = list(detail.get("_replay_packets_all") or detail.get("replay_packets") or [])
            sni = ""
            ja3 = ""
            cert_subject = ""
            cert_issuer = ""
            cert_window = ""
            tls_packet_hits = 0
            for pkt in pkts:
                fields = pkt.get("fields") or {}
                if not sni and fields.get("tls.sni"):
                    sni = str(fields.get("tls.sni"))
                if not ja3 and fields.get("tls.ja3_md5"):
                    ja3 = str(fields.get("tls.ja3_md5"))
                if not cert_subject and fields.get("tls.cert.subject"):
                    cert_subject = str(fields.get("tls.cert.subject"))
                if not cert_issuer and fields.get("tls.cert.issuer"):
                    cert_issuer = str(fields.get("tls.cert.issuer"))
                if not cert_window and (fields.get("tls.cert.not_before") or fields.get("tls.cert.not_after")):
                    cert_window = f"{fields.get('tls.cert.not_before', '')} -> {fields.get('tls.cert.not_after', '')}".strip(" ->")
                if any(k.startswith("tls.") for k in fields.keys()):
                    tls_packet_hits += 1
            has_tls_metadata = bool(sni or ja3 or cert_subject or cert_issuer or tls_packet_hits > 0)
            if has_keylog and has_tls_metadata:
                status = "decryptable_candidate"
                reason_code = "keylog_present_tls_metadata_present"
                decryptable += 1
                next_action = "Replay/decode this flow using the same capture-time keylog file."
            elif has_keylog and not has_tls_metadata:
                status = "unknown_tls_metadata"
                reason_code = "keylog_present_but_no_tls_metadata"
                next_action = "Capture more packets around the handshake (ClientHello/ServerHello)."
            elif not has_keylog and has_tls_metadata:
                status = "missing_keylog"
                reason_code = "tls_metadata_present_but_no_keylog"
                next_action = "Configure SSLKEYLOGFILE before capture and rerun collection."
            else:
                status = "insufficient_tls_signals"
                reason_code = "no_keylog_and_sparse_tls_metadata"
                next_action = "Validate filters/interface and capture complete TLS handshakes."
            diag = []
            if sni:
                diag.append(f"SNI={sni[:120]}")
            if ja3:
                diag.append(f"JA3={ja3}")
            if cert_subject:
                diag.append(f"cert_subject={cert_subject[:120]}")
            if cert_issuer:
                diag.append(f"cert_issuer={cert_issuer[:120]}")
            if cert_window:
                diag.append(f"cert_validity={cert_window[:140]}")
            diag.append(f"tls_packets_with_metadata={tls_packet_hits}")
            rows.append(
                {
                    "flow_id": fid,
                    "protocol": flow.get("protocol"),
                    "client": flow.get("client"),
                    "server": flow.get("server"),
                    "tls_sni": sni,
                    "tls_ja3": ja3,
                    "tls_cert_subject": cert_subject,
                    "tls_cert_issuer": cert_issuer,
                    "tls_cert_validity": cert_window,
                    "status": status,
                    "reason_code": reason_code,
                    "reason": (
                        "Scapy-only mode: keylog is configured and TLS metadata is present."
                        if status == "decryptable_candidate"
                        else "Scapy-only diagnostics suggest additional key/session material is required."
                    ),
                    "next_action": next_action,
                    "diagnostics": diag[:8],
                }
            )
        coverage_pct = round((decryptable / len(tls_flows)) * 100, 1) if tls_flows else 0.0
        keylog_checks = {
            "path": keylog,
            "exists": has_keylog,
            "size_bytes": keylog_size,
            "updated_at": keylog_mtime,
            "format_hint": "looks_valid" if (has_keylog and keylog_size > 0) else "missing_or_empty",
        }
        return {
            "config": cfg,
            "total_flows": len(selected),
            "tls_like_flows": len(tls_flows),
            "decryptable_candidates": decryptable,
            "decryptable_coverage_pct": coverage_pct,
            "engine": "scapy_only",
            "keylog_checks": keylog_checks,
            "notes": [
                "Decryption status is heuristic in Scapy-only mode.",
                "Forward-secret sessions usually need session secrets (e.g., SSLKEYLOGFILE) at capture time.",
            ],
            "items": rows,
        }

    def list_interfaces(self) -> Dict[str, Any]:
        interfaces = self._list_system_interfaces()
        if "any" not in interfaces:
            interfaces = ["any"] + interfaces
        return {
            "interfaces": interfaces,
            "source": "scapy/system",
            "capture_ready": self._can_import_scapy(),
            "warning": "" if interfaces else "No network interface detected.",
            "interface_help": {
                "any": "Resolves to Scapy default-route NIC (not Linux tcpdump multi-interface 'any').",
            },
        }

    def analyze_file(
        self,
        pcap: str,
        display_filter: Optional[str] = None,
        protocol_filter: Optional[str] = None,
        max_packets: Optional[int] = 2000,
        include_raw: bool = False,
        bpf_filter: Optional[str] = None,
        enable_fts: bool = False,
    ) -> Dict[str, Any]:
        try:
            from scapy.all import sniff
            from scapy.utils import PcapReader
        except Exception as exc:
            return {"error": f"Scapy is required: {exc}"}

        path = os.path.abspath(str(pcap or "").strip())
        if not path:
            return {"error": "pcap path is required"}
        if not os.path.isfile(path):
            return {"error": f"Capture not found: {path}"}

        self._last_source_pcap = path
        limit = self._safe_int(max_packets, 2000)
        bpf = str(bpf_filter or "").strip()

        def _read_with_pcapreader() -> List[Any]:
            items: List[Any] = []
            n = 0
            with PcapReader(path) as reader:
                for pkt in reader:
                    if limit and n >= limit:
                        break
                    items.append(pkt)
                    n += 1
            return items

        def _read_with_sniff() -> List[Any]:
            return list(sniff(offline=path, count=limit if limit else 0))

        def _iter_packets() -> Iterable[Any]:
            if bpf:
                try:
                    batch = sniff(offline=path, filter=bpf, count=limit if limit else 0)
                except Exception as exc:
                    raise RuntimeError(f"BPF filter rejected or unsupported: {exc}") from exc
                for pkt in batch or []:
                    yield pkt
                return
            reader_packets: List[Any] = []
            reader_error = ""
            try:
                reader_packets = _read_with_pcapreader()
            except Exception as exc:
                reader_error = str(exc)
            sniff_packets: List[Any] = []
            sniff_error = ""
            try:
                sniff_packets = _read_with_sniff()
            except Exception as exc:
                sniff_error = str(exc)
            best = sniff_packets if len(sniff_packets) > len(reader_packets) else reader_packets
            if not best:
                detail = f"PcapReader: {reader_error or 'no packets'} | sniff(offline): {sniff_error or 'no packets'}"
                raise RuntimeError(f"Unable to read capture: {detail}")
            for pkt in best:
                yield pkt

        try:
            packets = _iter_packets()
        except RuntimeError as exc:
            return {"error": str(exc), "pcap": path}

        return self._analyze_packet_iterable(
            packets=packets,
            source=path,
            display_filter=display_filter,
            protocol_filter=protocol_filter,
            max_packets=max_packets,
            include_raw=include_raw,
            bpf_filter=bpf or None,
            enable_fts=bool(enable_fts),
        )

    def start_live_capture(
        self,
        interface: str,
        display_filter: Optional[str] = None,
        protocol_filter: Optional[str] = None,
        max_packets: Optional[int] = 0,
        include_raw: bool = False,
        bpf_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self._can_import_scapy():
            return {"error": "Scapy is required for live capture", "error_code": "missing_scapy"}

        iface = str(interface or "").strip()
        if not iface:
            return {"error": "interface is required", "error_code": "missing_interface"}
        selected_iface = iface
        sniff_iface, capture_note = self._resolve_sniff_interface(selected_iface)

        with self._lock:
            if self._live_state["running"]:
                return {"error": "Live capture is already running", "error_code": "already_running", "live_capture": self.get_live_status()}
            self._live_stop.clear()
            self._live_flows = {}
            self._live_session_id = uuid.uuid4().hex
            bpf = str(bpf_filter or "").strip()
            self._live_state = {
                "running": True,
                "interface": selected_iface,
                "sniff_interface": sniff_iface,
                "capture_note": capture_note,
                "display_filter": str(display_filter or "").strip(),
                "bpf_filter": bpf,
                "protocol_filter": self._normalize_protocol_filter(protocol_filter),
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "observed_packets": 0,
                "processed_packets": 0,
                "packet_errors": 0,
                "include_raw": bool(include_raw),
                "max_packets": self._safe_int(max_packets, 0),
                "error": "",
                "warning": capture_note or "",
                "capture_backend": "scapy",
                "session_id": self._live_session_id,
            }
            self._live_thread = threading.Thread(
                target=self._live_capture_worker,
                args=(
                    sniff_iface,
                    str(display_filter or "").strip() or None,
                    self._live_state["protocol_filter"],
                    self._live_state["max_packets"],
                    bool(include_raw),
                    bpf or None,
                ),
                daemon=True,
            )
            self._live_thread.start()
        return {"status": "started", "live_capture": self.get_live_status()}

    def stop_live_capture(self) -> Dict[str, Any]:
        thread = None
        with self._lock:
            if not self._live_state["running"]:
                return {"status": "stopped", "live_capture": self.get_live_status()}
            self._live_stop.set()
            thread = self._live_thread
        if thread and thread.is_alive():
            thread.join(timeout=3.0)
        with self._lock:
            self._live_state["running"] = False
            self._live_thread = None
        return {"status": "stopped", "live_capture": self.get_live_status(), "analysis": self.get_live_snapshot()}

    def get_live_status(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._live_state)

    def get_live_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            summaries = []
            patterns: List[Dict[str, Any]] = []
            suggestions: List[Dict[str, Any]] = []
            cache: Dict[str, Dict[str, Any]] = {}
            for flow in self._live_flows.values():
                finalized = self._clone_and_finalize_flow(flow)
                flow_patterns = self._detect_patterns(finalized)
                finalized["patterns"] = flow_patterns
                finalized["risk_score"] = self._risk_score(flow_patterns)
                patterns.extend(flow_patterns)
                suggestions.extend(self._build_suggestions(finalized, flow_patterns))
                summaries.append(self._summarize_flow(finalized))
                cache[finalized["id"]] = self._build_flow_detail(finalized)
            summaries.sort(key=lambda item: (item.get("risk_score", 0), item.get("packet_count", 0)), reverse=True)
            self._analysis_cache = cache
            global_timeline = self._build_global_timeline(list(cache.values()), limit=400)
            snapshot = {
                "mode": "live",
                "live_capture": self.get_live_status(),
                "flow_count": len(summaries),
                "flows": summaries,
                "patterns": patterns,
                "suggestions": suggestions,
                "protocols": self._protocol_stats(summaries),
                "iocs": self._merge_iocs([detail.get("iocs", {}) for detail in cache.values()]),
                "endpoint_map": self._endpoint_map(summaries),
                "session_id": self._live_session_id,
                "global_timeline": global_timeline,
                "provenance": build_provenance(
                    None,
                    "live",
                    {"session_id": self._live_session_id, "interface": self._live_state.get("sniff_interface")},
                ),
            }
            snapshot["decryption"] = self.get_decryption_status(summaries)
            self._last_result = dict(snapshot)
            return snapshot

    def get_last_result(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._last_result)

    def list_recordings(self) -> Dict[str, Any]:
        recordings = []
        for name in sorted(os.listdir(self._recordings_dir), reverse=True):
            if not name.endswith(".json"):
                continue
            path = os.path.join(self._recordings_dir, name)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except Exception:
                continue
            meta = payload.get("meta", {})
            result = payload.get("result", {})
            recordings.append(
                {
                    "recording_id": meta.get("recording_id") or name[:-5],
                    "name": meta.get("name") or name[:-5],
                    "created_at": meta.get("created_at", ""),
                    "source_type": meta.get("source_type", "analysis"),
                    "flow_count": result.get("flow_count", 0),
                    "processed_packets": result.get("processed_packets", 0),
                    "protocols": [item.get("protocol") for item in (result.get("protocols", []) or [])[:8]],
                }
            )
        return {"recordings": recordings, "recordings_dir": self._recordings_dir}

    def save_recording(self, name: Optional[str] = None, source_type: str = "analysis") -> Dict[str, Any]:
        bundle = self._build_recording_bundle(name=name, source_type=source_type)
        if not bundle.get("result"):
            return {"error": "No analysis context available yet"}
        recording_id = bundle["meta"]["recording_id"]
        path = os.path.join(self._recordings_dir, f"{recording_id}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(bundle, handle, indent=2, ensure_ascii=False)
        self._last_recording_bundle = bundle
        return {"status": "saved", "recording_id": recording_id, "path": path, "meta": bundle["meta"]}

    def load_recording(self, recording_id: str) -> Dict[str, Any]:
        payload = self._read_recording(recording_id)
        if "error" in payload:
            return payload
        raw_flows = dict(payload.get("flow_details", {}) or {})
        self._analysis_cache = {fid: self._hydrate_flow_detail_for_session(d) for fid, d in raw_flows.items()}
        self._last_result = dict(payload.get("result", {}) or {})
        self._last_recording_bundle = payload
        return {"status": "loaded", "recording": payload.get("meta", {}), "result": self.get_last_result()}

    def replay_recording(self, recording_id: str, cursor: int = 0, limit: int = 25, flow_id: Optional[str] = None) -> Dict[str, Any]:
        payload = self._read_recording(recording_id)
        if "error" in payload:
            return payload
        stream = list(payload.get("replay_stream", []) or [])
        target_flow_id = str(flow_id or "").strip()
        if target_flow_id:
            stream = [item for item in stream if item.get("flow_id") == target_flow_id]
        safe_cursor = max(0, self._safe_int(cursor, 0))
        safe_limit = max(1, min(self._safe_int(limit, 25), 200))
        events = stream[safe_cursor:safe_cursor + safe_limit]
        next_cursor = safe_cursor + len(events)
        return {
            "recording": payload.get("meta", {}),
            "flow_id": target_flow_id,
            "cursor": safe_cursor,
            "limit": safe_limit,
            "total": len(stream),
            "next_cursor": next_cursor,
            "has_more": next_cursor < len(stream),
            "events": events,
        }

    def query_result(
        self,
        base: Dict[str, Any],
        protocol_filter: Optional[str] = None,
        severity_filter: Optional[str] = None,
        host_filter: Optional[str] = None,
        port_filter: Optional[str] = None,
        search: Optional[str] = None,
        flow_page: int = 1,
        flow_per_page: int = 25,
        finding_page: int = 1,
        finding_per_page: int = 30,
        suggestion_page: int = 1,
        suggestion_per_page: int = 20,
    ) -> Dict[str, Any]:
        result = dict(base or {})
        flows = list(result.get("flows", []) or [])
        patterns = list(result.get("patterns", []) or [])
        suggestions = list(result.get("suggestions", []) or [])

        protocol_set = {item.lower() for item in self._normalize_protocol_filter(protocol_filter)}
        severity_set = {item.lower() for item in self._normalize_severity_filter(severity_filter)}
        host_token = str(host_filter or "").strip().lower()
        search_token = str(search or "").strip().lower()
        port_value = self._safe_int(port_filter, 0) if str(port_filter or "").strip() else 0

        # Fast path: pagination only (avoids subtle filter / empty-set edge cases in the UI).
        if not protocol_set and not severity_set and not host_token and not port_value and not search_token:
            normalized_patterns = self._normalize_patterns_for_display(patterns, flows)
            flow_page_data = self._paginate(flows, flow_page, flow_per_page)
            finding_page_data = self._paginate(normalized_patterns, finding_page, finding_per_page)
            suggestion_page_data = self._paginate(suggestions, suggestion_page, suggestion_per_page)
            result["flow_count"] = len(flows)
            result["flows"] = flow_page_data["items"]
            result["patterns"] = finding_page_data["items"]
            result["suggestions"] = suggestion_page_data["items"]
            result["protocols"] = self._protocol_stats(flows)
            result["iocs"] = self._merge_iocs([flow.get("iocs", {}) for flow in flows])
            result["endpoint_map"] = self._endpoint_map(flows)
            result["pagination"] = {
                "flows": flow_page_data["meta"],
                "findings": finding_page_data["meta"],
                "suggestions": suggestion_page_data["meta"],
            }
            result["filters"] = {
                "protocol_filter": [],
                "severity_filter": [],
                "host_filter": "",
                "port_filter": "",
                "search": "",
            }
            return result

        def _flow_match(flow: Dict[str, Any]) -> bool:
            proto = str(flow.get("protocol", "")).lower()
            client = str(flow.get("client", "")).lower()
            server = str(flow.get("server", "")).lower()
            text_blob = " ".join(
                [
                    proto,
                    client,
                    server,
                    str(flow.get("request_preview", "")).lower(),
                    str(flow.get("response_preview", "")).lower(),
                    str(flow.get("narrative", "")).lower(),
                    json.dumps(flow.get("iocs", {}), ensure_ascii=False).lower(),
                ]
            )
            if protocol_set and proto not in protocol_set:
                return False
            if host_token and host_token not in client and host_token not in server:
                return False
            if port_value and f":{port_value}" not in client and f":{port_value}" not in server:
                return False
            if search_token and search_token not in text_blob:
                return False
            return True

        filtered_flows = [flow for flow in flows if _flow_match(flow)]
        allowed_flow_ids = {flow.get("id") for flow in filtered_flows}

        def _pattern_match(pattern: Dict[str, Any]) -> bool:
            if allowed_flow_ids and pattern.get("flow_id") not in allowed_flow_ids:
                return False
            severity = str(pattern.get("severity", "")).lower()
            if severity_set and severity not in severity_set:
                return False
            if search_token:
                blob = " ".join(
                    [
                        str(pattern.get("type", "")).lower(),
                        str(pattern.get("message", "")).lower(),
                        " ".join(str(item).lower() for item in (pattern.get("evidence") or [])),
                    ]
                )
                if search_token not in blob:
                    return False
            return True

        filtered_patterns = [pattern for pattern in patterns if _pattern_match(pattern)]
        normalized_patterns = self._normalize_patterns_for_display(filtered_patterns, filtered_flows)
        flow_level_filters = bool(protocol_set or host_token or port_value or search_token)
        if not flow_level_filters:
            filtered_suggestions = list(suggestions)
        else:
            filtered_suggestions = [item for item in suggestions if item.get("flow_id") in allowed_flow_ids]

        flow_page_data = self._paginate(filtered_flows, flow_page, flow_per_page)
        finding_page_data = self._paginate(normalized_patterns, finding_page, finding_per_page)
        suggestion_page_data = self._paginate(filtered_suggestions, suggestion_page, suggestion_per_page)

        result["flow_count"] = len(filtered_flows)
        result["flows"] = flow_page_data["items"]
        result["patterns"] = finding_page_data["items"]
        result["suggestions"] = suggestion_page_data["items"]
        result["protocols"] = self._protocol_stats(filtered_flows)
        result["iocs"] = self._merge_iocs([flow.get("iocs", {}) for flow in filtered_flows])
        result["endpoint_map"] = self._endpoint_map(filtered_flows)
        result["decryption"] = self.get_decryption_status(filtered_flows)
        result["pagination"] = {
            "flows": flow_page_data["meta"],
            "findings": finding_page_data["meta"],
            "suggestions": suggestion_page_data["meta"],
        }
        result["filters"] = {
            "protocol_filter": sorted(protocol_set),
            "severity_filter": sorted(severity_set),
            "host_filter": host_filter or "",
            "port_filter": port_value or "",
            "search": search or "",
        }
        return result

    def build_report(self, result: Dict[str, Any], report_format: str = "json") -> str:
        fmt = str(report_format or "json").strip().lower()
        enriched: Dict[str, Any] = dict(result or {})
        sid = str(enriched.get("session_id") or "").strip()
        if sid:
            enriched["annotations"] = self.investigation.annotations_for_session(sid)
        if fmt == "html":
            flows = enriched.get("flows", []) or []
            patterns = enriched.get("patterns", []) or []
            proto_stats = enriched.get("protocols", []) or []
            prov_block = ""
            prov = enriched.get("provenance")
            if isinstance(prov, dict) and prov:
                prov_block = (
                    "<h2>Provenance</h2><pre style='background:#f8f8f8;padding:12px;overflow:auto;'>"
                    + json.dumps(prov, indent=2, ensure_ascii=False)
                    + "</pre>"
                )
            ann = enriched.get("annotations") or []
            ann_block = ""
            if ann:
                ann_block = "<h2>Annotations</h2><ul>" + "".join(
                    f"<li><strong>{item.get('status', 'to verify')}</strong> "
                    f"{item.get('flow_id', '')}: {(item.get('note') or '')[:500]}</li>"
                    for item in ann[:50]
                ) + "</ul>"
            iocs = enriched.get("iocs") or {}
            ioc_block = ""
            if isinstance(iocs, dict) and iocs:
                ioc_rows = []
                for kind, values in iocs.items():
                    vals = ", ".join(str(v) for v in (values or [])[:30])
                    if vals:
                        ioc_rows.append(f"<tr><td>{kind}</td><td>{vals}</td></tr>")
                if ioc_rows:
                    ioc_block = "<h2>IOC</h2><table><tbody>" + "".join(ioc_rows) + "</tbody></table>"
            risk_total = sum(int(flow.get("risk_score", 0) or 0) for flow in flows)
            high_risk = [flow for flow in flows if int(flow.get("risk_score", 0) or 0) >= 5]
            executive = (
                "<h2>Executive Summary</h2>"
                "<ul>"
                f"<li>Analyzed flows: <strong>{len(flows)}</strong> (including {len(high_risk)} high-risk).</li>"
                f"<li>Detected findings: <strong>{len(patterns)}</strong>.</li>"
                f"<li>Volume packets: <strong>{enriched.get('processed_packets', 0)}</strong>.</li>"
                f"<li>Cumulative risk: <strong>{risk_total}</strong>.</li>"
                "</ul>"
            )
            rows = "".join(
                f"<tr><td>{item.get('protocol')}</td><td>{item.get('flow_count')}</td><td>{item.get('packet_count')}</td><td>{item.get('risk_score')}</td></tr>"
                for item in proto_stats[:12]
            )
            finding_rows = "".join(
                f"<li><strong>{item.get('severity', '').upper()}</strong> {item.get('type', '')}: {item.get('message', '')}</li>"
                for item in patterns[:25]
            )
            flow_rows = "".join(
                "<li>"
                f"<strong>{flow.get('protocol')}</strong> {flow.get('client')} -> {flow.get('server')} "
                f"(risk {flow.get('risk_score', 0)}, packets {flow.get('packet_count', 0)})"
                f"<br><span style='color:#555;'>{(flow.get('narrative') or '')[:260]}</span>"
                "</li>"
                for flow in flows[:25]
            )
            top_risk_rows = "".join(
                f"<li><strong>{flow.get('protocol')}</strong> {flow.get('client')} -> {flow.get('server')} "
                f"(risk {flow.get('risk_score', 0)}, packets {flow.get('packet_count', 0)})</li>"
                for flow in sorted(flows, key=lambda x: (int(x.get("risk_score", 0) or 0), int(x.get("packet_count", 0) or 0)), reverse=True)[:10]
            )
            top_assets_counter = Counter()
            for flow in flows:
                top_assets_counter[str(flow.get("server") or "?")] += int(flow.get("risk_score", 0) or 0) + max(1, int(flow.get("packet_count", 0) or 0) // 20)
            top_assets_rows = "".join(
                f"<li>{asset} (exposure score {score})</li>"
                for asset, score in top_assets_counter.most_common(10)
            )
            recommendations = [
                "Review and prioritize high-risk flows with repeated authentication or credential findings.",
                "Pivot from high-confidence TLS/HTTP/SSH flows and validate protocol-specific controls.",
                "Investigate IOC clusters (domains, IPs, hashes) and block confirmed malicious indicators.",
            ]
            rec_rows = "".join(f"<li>{item}</li>" for item in recommendations)
            reason_rows = []
            for flow in flows[:20]:
                reasons = flow.get("risk_reasons") or []
                if not reasons:
                    continue
                tops = ", ".join(
                    f"+{r.get('points', 0)} {r.get('type', '')}"
                    for r in reasons[:4]
                )
                reason_rows.append(
                    "<tr>"
                    f"<td>{flow.get('protocol')} {flow.get('client')} -> {flow.get('server')}</td>"
                    f"<td>{flow.get('risk_score', 0)}</td>"
                    f"<td>{tops}</td>"
                    "</tr>"
                )
            reason_block = ""
            if reason_rows:
                reason_block = (
                    "<h2>Explained suspicion score</h2>"
                    "<table><thead><tr><th>Flows</th><th>Score</th><th>Principales contributions</th></tr></thead>"
                    f"<tbody>{''.join(reason_rows)}</tbody></table>"
                )
            return (
                "<!doctype html><html><head><meta charset='utf-8'><title>KittyProtocol Report</title>"
                "<style>body{font-family:Arial,sans-serif;margin:24px;}table{border-collapse:collapse;width:100%;}"
                "th,td{border:1px solid #ddd;padding:8px;vertical-align:top;}th{background:#f5f5f5;}h1,h2{margin-bottom:8px;}ul{line-height:1.5;}</style>"
                "</head><body>"
                f"<h1>KittyProtocol Report</h1><p>Flows: {len(flows)} | Findings: {len(patterns)} | Packets: {enriched.get('processed_packets', 0)}</p>"
                f"{executive}{prov_block}{ann_block}{ioc_block}{reason_block}"
                "<h2>Protocol Risk Summary</h2><table><thead><tr><th>Protocol</th><th>Flows</th><th>Packets</th><th>Risk</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
                f"<h2>Top Risks</h2><ul>{top_risk_rows or '<li>No high-risk flow</li>'}</ul>"
                f"<h2>Top Assets Affected</h2><ul>{top_assets_rows or '<li>No asset</li>'}</ul>"
                f"<h2>Recommended Actions</h2><ul>{rec_rows}</ul>"
                f"<h2>Top Flows</h2><ul>{flow_rows or '<li>No flows</li>'}</ul>"
                f"<h2>Top Findings</h2><ul>{finding_rows or '<li>No findings</li>'}</ul>"
                "</body></html>"
            )

        return json.dumps(enriched, indent=2, ensure_ascii=False)

    def _build_recording_bundle(self, name: Optional[str], source_type: str) -> Dict[str, Any]:
        with self._lock:
            result = dict(self._last_result)
            flow_details = dict(self._analysis_cache)
        if not result:
            return {"meta": {}, "result": {}, "flow_details": {}, "replay_stream": []}
        created_at = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        recording_id = self._slugify(name or f"kittyprotocol-{source_type}-{created_at}")
        flow_details_public = {fid: self._flow_detail_for_persistence(d) for fid, d in flow_details.items()}
        return {
            "meta": {
                "recording_id": recording_id,
                "name": name or recording_id,
                "created_at": created_at,
                "source_type": source_type,
                "app": "kittyprotocol",
                "session_id": result.get("session_id", ""),
            },
            "result": result,
            "flow_details": flow_details_public,
            "replay_stream": self._build_replay_stream(flow_details_public),
            "provenance": result.get("provenance"),
        }

    def _build_replay_stream(self, flow_details: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        for flow_id, detail in (flow_details or {}).items():
            packets_src = detail.get("_replay_packets_all") or detail.get("replay_packets") or []
            for packet in packets_src:
                events.append(
                    {
                        "flow_id": flow_id,
                        "protocol": detail.get("protocol"),
                        "client": detail.get("client"),
                        "server": detail.get("server"),
                        "packet_number": packet.get("number"),
                        "timestamp": packet.get("timestamp"),
                        "direction": packet.get("direction"),
                        "summary": packet.get("summary"),
                        "src": packet.get("src"),
                        "dst": packet.get("dst"),
                        "length": packet.get("length"),
                        "payload_excerpt": packet.get("payload_excerpt", ""),
                        "fields": packet.get("fields", {}),
                    }
                )
        events.sort(key=lambda item: (item.get("timestamp", ""), self._safe_int(item.get("packet_number"), 0)))
        for index, event in enumerate(events, start=1):
            event["index"] = index
        return events

    def _read_recording(self, recording_id: str) -> Dict[str, Any]:
        safe_id = self._slugify(recording_id)
        if not safe_id:
            return {"error": "recording_id is required"}
        path = os.path.join(self._recordings_dir, f"{safe_id}.json")
        if not os.path.isfile(path):
            return {"error": f"Recording not found: {safe_id}"}
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception as exc:
            return {"error": f"Unable to read recording: {exc}"}

    def get_flow_detail(self, flow_id: str) -> Dict[str, Any]:
        flow = self._analysis_cache.get(str(flow_id or "").strip())
        if not flow:
            return {"error": "Flow not found"}
        return {k: v for k, v in flow.items() if not str(k).startswith("_")}

    def get_ioc_summary(self, protocol_filter: Optional[str] = None, host_filter: Optional[str] = None) -> Dict[str, Any]:
        flows = list(self._last_result.get("flows", []) or [])
        protocol_set = {item.lower() for item in self._normalize_protocol_filter(protocol_filter)}
        host_token = str(host_filter or "").strip().lower()
        if protocol_set:
            flows = [flow for flow in flows if str(flow.get("protocol", "")).lower() in protocol_set]
        if host_token:
            flows = [
                flow
                for flow in flows
                if host_token in str(flow.get("client", "")).lower() or host_token in str(flow.get("server", "")).lower()
            ]
        flow_details = [self._analysis_cache.get(str(flow.get("id") or ""), {}) for flow in flows]
        iocs = self._merge_iocs([item.get("iocs", {}) for item in flow_details if isinstance(item, dict)])
        counts = {k: len(v or []) for k, v in iocs.items()}
        mitre_map = {
            "ips": ["T1071", "T1041"],
            "domains": ["T1071.001", "T1568"],
            "urls": ["T1071.001", "T1105"],
            "emails": ["T1566"],
            "hashes": ["T1553.004", "T1027"],
        }
        return {
            "flow_count": len(flows),
            "ioc_counts": counts,
            "iocs": iocs,
            "mitre_mapping": mitre_map,
        }

    def get_flow_packets_page(self, flow_id: str, offset: Any = 0, limit: Any = 100) -> Dict[str, Any]:
        detail = self._analysis_cache.get(str(flow_id or "").strip())
        if not detail:
            return {"error": "Flow not found"}
        all_packets = list(detail.get("_replay_packets_all") or detail.get("replay_packets") or [])
        off = max(0, self._safe_int(offset, 0))
        lim = max(1, min(self._safe_int(limit, 100), 500))
        page = all_packets[off : off + lim]
        return {
            "flow_id": flow_id,
            "total": len(all_packets),
            "offset": off,
            "limit": lim,
            "packets": page,
        }

    def get_flow_packet_hex_from_pcap(self, flow_id: str, flow_packet_index: int, max_bytes: int = 8192) -> Dict[str, Any]:
        detail = self._analysis_cache.get(str(flow_id or "").strip())
        if not detail:
            return {"error": "Flow not found"}
        all_packets = detail.get("_replay_packets_all") or detail.get("replay_packets") or []
        total_flow = len(all_packets)
        idx = self._safe_int(flow_packet_index, -1)
        if total_flow <= 0 or idx < 0 or idx >= total_flow:
            return {"error": "flow_packet_index is out of bounds"}
        path = self._last_source_pcap
        if not path or not os.path.isfile(path):
            return {
                "error": "No source PCAP file for this session (re-run analysis on the same file, or hex is unavailable after loading a JSON recording without PCAP).",
            }
        c_ip, c_port = self._parse_endpoint(str(detail.get("client", "")))
        s_ip, s_port = self._parse_endpoint(str(detail.get("server", "")))
        cap = max(64, min(self._safe_int(max_bytes, 8192), 262144))
        try:
            from scapy.utils import PcapReader

            matched_ordinal = 0
            with PcapReader(path) as reader:
                for pkt in reader:
                    if not self._packet_matches_flow_endpoints(pkt, c_ip, c_port, s_ip, s_port):
                        continue
                    if matched_ordinal == idx:
                        full = bytes(pkt)
                        chunk = full[:cap]
                        return {
                            "flow_id": flow_id,
                            "flow_packet_index": idx,
                            "total_length": len(full),
                            "returned_length": len(chunk),
                            "truncated": len(chunk) < len(full),
                            "hex": chunk.hex(),
                        }
                    matched_ordinal += 1
        except Exception as exc:
            return {"error": f"Play PCAP: {exc}"}
        return {
            "error": "Frame not found in the PCAP (BPF filter or packet-limit analysis may desynchronize frame order from the full file).",
        }

    def _packet_matches_flow_endpoints(self, pkt: Any, c_ip: str, c_port: int, s_ip: str, s_port: int) -> bool:
        src_ip, dst_ip = self._get_ips(pkt)
        if not src_ip or not dst_ip:
            return False
        sp = self._get_port(pkt, "sport")
        dp = self._get_port(pkt, "dport")
        ends = {(src_ip, sp), (dst_ip, dp)}
        return ends == {(c_ip, c_port), (s_ip, s_port)}

    def _flow_detail_for_persistence(self, detail: Dict[str, Any]) -> Dict[str, Any]:
        out = {k: v for k, v in detail.items() if not str(k).startswith("_")}
        full = detail.get("_replay_packets_all")
        if full is not None:
            out["replay_packets"] = list(full)
            out["replay_packets_total"] = len(full)
        return out

    def _hydrate_flow_detail_for_session(self, detail: Dict[str, Any]) -> Dict[str, Any]:
        d = dict(detail or {})
        rp = [dict(p) for p in (d.get("replay_packets") or [])]
        for i, pkt in enumerate(rp):
            pkt.setdefault("flow_packet_index", i)
        d["_replay_packets_all"] = rp
        total = len(rp)
        d["replay_packets_total"] = int(d.get("replay_packets_total") or total)
        cap = self.REPLAY_PACKETS_CLIENT_CAP
        d["replay_packets"] = rp[:cap] if len(rp) > cap else rp
        return d

    def _live_capture_worker(
        self,
        interface: Optional[str],
        display_filter: Optional[str],
        protocol_filter: List[str],
        max_packets: int,
        include_raw: bool,
        bpf_filter: Optional[str],
    ) -> None:
        try:
            from scapy.all import sniff

            def _handle_packet(packet):
                if self._live_stop.is_set():
                    return True
                try:
                    with self._lock:
                        self._live_state["observed_packets"] += 1
                    if not self._packet_matches_filter(packet, display_filter, protocol_filter):
                        self._refresh_live_warning()
                        return False
                    flow_key, packet_info = self._packet_to_record(packet, include_raw)
                    if not flow_key or not packet_info:
                        self._refresh_live_warning()
                        return False
                    with self._lock:
                        flow = self._live_flows.setdefault(flow_key, self._new_flow(flow_key, packet_info))
                        self._add_packet_to_flow(flow, packet_info)
                        self._live_state["processed_packets"] += 1
                        if max_packets and self._live_state["processed_packets"] >= max_packets:
                            self._live_stop.set()
                        self._refresh_live_warning()
                    self._emit_live_update_if_needed()
                    return False
                except Exception:
                    with self._lock:
                        self._live_state["packet_errors"] += 1
                        self._refresh_live_warning()
                    return False

            sniff_kwargs: Dict[str, Any] = {
                "iface": interface,
                "prn": _handle_packet,
                "store": False,
                "promisc": True,
                "stop_filter": lambda _pkt: self._live_stop.is_set(),
            }
            if bpf_filter:
                sniff_kwargs["filter"] = bpf_filter
            sniff(**sniff_kwargs)
        except PermissionError as exc:
            with self._lock:
                self._live_state["error"] = (
                    f"Capture permission denied ({exc}). "
                    "Run KittyProtocol as root or grant CAP_NET_RAW (and CAP_NET_ADMIN if needed) to the Python binary."
                )
                self._refresh_live_warning()
        except Exception as exc:
            with self._lock:
                self._live_state["error"] = str(exc)
                self._refresh_live_warning()
        finally:
            with self._lock:
                self._live_state["running"] = False
                self._refresh_live_warning()

    def _analyze_packet_iterable(
        self,
        packets,
        source: str,
        display_filter: Optional[str],
        protocol_filter: Optional[str],
        max_packets: Optional[int],
        include_raw: bool,
        bpf_filter: Optional[str] = None,
        enable_fts: bool = False,
    ) -> Dict[str, Any]:
        packet_limit = self._safe_int(max_packets, 2000)
        protocol_filter_tokens = self._normalize_protocol_filter(protocol_filter)
        flows: Dict[str, Dict[str, Any]] = {}
        processed = 0
        packet_errors = 0
        session_id = uuid.uuid4().hex
        self._session_id = session_id

        if self._payload_index:
            self._payload_index.close()
        fts: Optional[PayloadIndex] = None
        if enable_fts:
            fts = PayloadIndex()
            fts.start()
            self._payload_index = fts

        prov = build_provenance(
            source if source and os.path.isfile(str(source)) else None,
            "pcap" if source and os.path.isfile(str(source)) else "analysis",
            {"session_id": session_id, "bpf_filter": bpf_filter or ""},
        )

        for packet in packets:
            if packet_limit and processed >= packet_limit:
                break
            try:
                if not self._packet_matches_filter(packet, display_filter, protocol_filter_tokens):
                    continue
                flow_key, packet_info = self._packet_to_record(packet, include_raw)
                if not flow_key or not packet_info:
                    continue
                flow = flows.setdefault(flow_key, self._new_flow(flow_key, packet_info))
                self._add_packet_to_flow(flow, packet_info)
                if fts:
                    blob = self._normalize_text_blob(packet_info.get("fields") or {})
                    fts.add(flow_key, int(packet_info.get("number") or 0), blob)
                processed += 1
            except Exception as exc:
                packet_errors += 1
                if packet_errors <= 3:
                    print(f"[ERROR] Failed to process packet #{processed + packet_errors}: {exc}")

        if fts:
            fts.commit()

        summaries = []
        patterns: List[Dict[str, Any]] = []
        suggestions: List[Dict[str, Any]] = []
        cache: Dict[str, Dict[str, Any]] = {}
        for flow in flows.values():
            self._finalize_flow(flow)
            flow_patterns = self._detect_patterns(flow)
            flow["patterns"] = flow_patterns
            flow["risk_score"] = self._risk_score(flow_patterns)
            patterns.extend(flow_patterns)
            suggestions.extend(self._build_suggestions(flow, flow_patterns))
            summaries.append(self._summarize_flow(flow))
            cache[flow["id"]] = self._build_flow_detail(flow)

        summaries.sort(key=lambda item: (item.get("risk_score", 0), item.get("packet_count", 0)), reverse=True)
        self._analysis_cache = cache
        global_timeline = self._build_global_timeline(list(flows.values()), limit=500)

        self._render_console(summaries, patterns, suggestions)
        result = {
            "pcap": source,
            "display_filter": display_filter,
            "bpf_filter": bpf_filter or "",
            "protocol_filter": protocol_filter_tokens,
            "processed_packets": processed,
            "packet_errors": packet_errors,
            "flow_count": len(summaries),
            "flows": summaries,
            "patterns": patterns,
            "suggestions": suggestions,
            "protocols": self._protocol_stats(summaries),
            "iocs": self._merge_iocs([detail.get("iocs", {}) for detail in cache.values()]),
            "endpoint_map": self._endpoint_map(summaries),
            "session_id": session_id,
            "provenance": prov,
            "global_timeline": global_timeline,
            "fts_indexed": bool(enable_fts),
            "filter_docs": self.bpf_display_filter_help(),
        }
        result["decryption"] = self.get_decryption_status(summaries)
        if include_raw:
            result["raw_flows"] = [self._export_raw_flow(flow) for flow in flows.values()]
        self._last_result = dict(result)
        return result

    def _emit_live_update_if_needed(self) -> None:
        callback = self._live_update_callback
        if callback is None:
            return
        now = time.time()
        if now - self._last_live_emit_ts < 1.2:
            return
        self._last_live_emit_ts = now
        try:
            callback(self.get_live_snapshot())
        except Exception:
            pass

    def _refresh_live_warning(self) -> None:
        observed = int(self._live_state.get("observed_packets", 0) or 0)
        processed = int(self._live_state.get("processed_packets", 0) or 0)
        running = bool(self._live_state.get("running"))
        error = str(self._live_state.get("error", "") or "")
        if error:
            self._live_state["warning"] = error
            return
        if running and observed == 0:
            self._live_state["warning"] = "No packet observed yet. Verify the interface, traffic source, or capture permissions."
            return
        if observed > 0 and processed == 0:
            self._live_state["warning"] = "Packets are seen, but none matched KittyProtocol flow extraction. Relax the filters or try interface 'any'."
            return
        self._live_state["warning"] = ""

    def _packet_matches_filter(self, packet, display_filter: Optional[str], protocol_filter: Optional[List[str]] = None) -> bool:
        filt = str(display_filter or "").strip().lower()
        proto = self._infer_protocol(packet, "", self._get_port(packet, "sport"), self._get_port(packet, "dport")).lower()
        accepted = {item.lower() for item in (protocol_filter or []) if item}
        if accepted and proto not in accepted:
            return False
        if not filt:
            return True
        summary = self._scapy_text(packet).lower()
        if filt in summary:
            return True
        # Also check if filter matches the inferred protocol explicitly
        if filt in proto:
            return True
        return False

    def _new_flow(self, flow_key: str, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        client, server = self._guess_client_server(packet_info)
        return {
            "id": flow_key,
            "protocol": packet_info["protocol"],
            "transport": packet_info["transport"],
            "client": client,
            "server": server,
            "packet_count": 0,
            "requests": [],
            "responses": [],
            "packets": [],
            "packet_sizes": [],
            "auth_related_packets": 0,
            "nonce_related_packets": 0,
        }

    def _add_packet_to_flow(self, flow: Dict[str, Any], packet_info: Dict[str, Any]) -> None:
        flow["packet_count"] += 1
        flow["packet_sizes"].append(packet_info["length"])
        flow["packets"].append(packet_info)
        if packet_info["direction"] == "response":
            flow["responses"].append(packet_info)
        else:
            flow["requests"].append(packet_info)
        if packet_info["auth_hint"]:
            flow["auth_related_packets"] += 1
        if packet_info["nonce_hint"]:
            flow["nonce_related_packets"] += 1

    def _finalize_flow(self, flow: Dict[str, Any]) -> None:
        def _ts_key(item: Dict[str, Any]) -> Tuple[float, int]:
            return (float(item.get("timestamp_epoch", 0) or 0.0), int(item.get("number") or 0))

        flow["requests"].sort(key=_ts_key)
        flow["responses"].sort(key=_ts_key)
        flow["packets"].sort(key=_ts_key)
        flow["protocol"] = self._dominant_protocol_from_packets(flow)
        flow["unique_request_signatures"] = Counter(pkt["signature"] for pkt in flow["requests"] if pkt["signature"])
        flow["avg_packet_size"] = sum(flow["packet_sizes"]) / len(flow["packet_sizes"]) if flow["packet_sizes"] else 0.0
        flow["std_packet_size"] = self._stddev(flow["packet_sizes"])
        flow["timeline"] = self._build_flow_timeline(flow)
        confidences = [int(pkt.get("protocol_confidence", 0) or 0) for pkt in flow.get("packets", []) if pkt.get("protocol_confidence") is not None]
        flow["protocol_confidence"] = round(sum(confidences) / len(confidences), 1) if confidences else 0.0
        evidence_counter: Counter = Counter()
        for pkt in flow.get("packets", [])[:80]:
            for reason in pkt.get("protocol_evidence", [])[:4]:
                if reason:
                    evidence_counter[str(reason)] += 1
        flow["protocol_why"] = [{"reason": reason, "count": count} for reason, count in evidence_counter.most_common(8)]

    def _summarize_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        first_request = flow["requests"][0] if flow["requests"] else None
        first_response = flow["responses"][0] if flow["responses"] else None
        packets = flow.get("packets", [])
        iocs = self._extract_iocs_from_flow(flow)
        return {
            "id": flow["id"],
            "protocol": flow["protocol"],
            "transport": flow["transport"],
            "client": flow["client"],
            "server": flow["server"],
            "packet_count": flow["packet_count"],
            "request_count": len(flow["requests"]),
            "response_count": len(flow["responses"]),
            "avg_packet_size": round(flow["avg_packet_size"], 2),
            "timeline": flow["timeline"],
            "patterns": flow.get("patterns", []),
            "risk_score": flow.get("risk_score", 0),
            "request_preview": first_request["summary"] if first_request else "",
            "response_preview": first_response["summary"] if first_response else "",
            "first_seen": packets[0]["timestamp"] if packets else "",
            "last_seen": packets[-1]["timestamp"] if packets else "",
            "duration_seconds": self._duration_seconds(packets),
            "framework_actions": self._framework_actions(flow),
            "risk_reasons": self._risk_reasons(flow.get("patterns", [])),
            "narrative": self._flow_narrative(flow, flow.get("patterns", [])),
            "iocs": iocs,
            "ioc_count": sum(len(v) for v in iocs.values()),
            "protocol_confidence": flow.get("protocol_confidence", 0.0),
            "protocol_why": flow.get("protocol_why", []),
        }

    def _export_raw_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": flow["id"],
            "protocol": flow["protocol"],
            "client": flow["client"],
            "server": flow["server"],
            "requests": flow["requests"],
            "responses": flow["responses"],
            "timeline": flow["timeline"],
            "patterns": flow.get("patterns", []),
        }

    def _build_flow_detail(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        def _packet_detail(pkt: Dict[str, Any], flow_packet_index: Optional[int] = None) -> Dict[str, Any]:
            row: Dict[str, Any] = {
                "number": pkt.get("number"),
                "timestamp": pkt.get("timestamp"),
                "timestamp_epoch": pkt.get("timestamp_epoch"),
                "direction": pkt.get("direction"),
                "summary": pkt.get("summary"),
                "src": pkt.get("src"),
                "dst": pkt.get("dst"),
                "length": pkt.get("length"),
                "fields": pkt.get("fields", {}),
                "payload_excerpt": pkt.get("payload_excerpt", ""),
            }
            if flow_packet_index is not None:
                row["flow_packet_index"] = int(flow_packet_index)
            return row

        packets = flow.get("packets", [])
        requests = flow.get("requests", [])
        responses = flow.get("responses", [])
        replay_all = [_packet_detail(pkt, i) for i, pkt in enumerate(packets)]
        cap = self.REPLAY_PACKETS_CLIENT_CAP
        detail = {
            "id": flow["id"],
            "protocol": flow["protocol"],
            "transport": flow["transport"],
            "client": flow["client"],
            "server": flow["server"],
            "packet_count": flow["packet_count"],
            "request_count": len(requests),
            "response_count": len(responses),
            "timeline": flow.get("timeline", []),
            "patterns": flow.get("patterns", []),
            "risk_score": flow.get("risk_score", 0),
            "first_seen": packets[0].get("timestamp") if packets else "",
            "last_seen": packets[-1].get("timestamp") if packets else "",
            "duration_seconds": self._duration_seconds(packets),
            "framework_actions": self._framework_actions(flow),
            "requests": [_packet_detail(pkt) for pkt in requests[:20]],
            "responses": [_packet_detail(pkt) for pkt in responses[:20]],
            "packet_preview": [_packet_detail(pkt) for pkt in packets[:40]],
            "replay_packets": replay_all[:cap],
            "replay_packets_total": len(replay_all),
            "_replay_packets_all": replay_all,
            "field_summary": self._merge_field_summary(packets),
            "conversation": self._build_conversation(flow),
            "risk_reasons": self._risk_reasons(flow.get("patterns", [])),
            "narrative": self._flow_narrative(flow, flow.get("patterns", [])),
            "iocs": self._extract_iocs_from_flow(flow),
            "protocol_views": self._protocol_views(flow),
            "endpoint_map": self._endpoint_map([self._summarize_flow(flow)]),
            "protocol_confidence": flow.get("protocol_confidence", 0.0),
            "protocol_why": flow.get("protocol_why", []),
        }
        return detail

    def _build_conversation(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        packets = flow.get("packets", []) or []
        requests = flow.get("requests", []) or []
        responses = flow.get("responses", []) or []
        methods = Counter(
            pkt.get("fields", {}).get("http.request_method", "")
            for pkt in requests
            if pkt.get("fields", {}).get("http.request_method")
        )
        codes = Counter(
            pkt.get("fields", {}).get("http.response_code", "")
            for pkt in responses
            if pkt.get("fields", {}).get("http.response_code")
        )
        return {
            "first_seen": packets[0].get("timestamp") if packets else "",
            "last_seen": packets[-1].get("timestamp") if packets else "",
            "duration_seconds": self._duration_seconds(packets),
            "request_methods": [{"name": key, "count": value} for key, value in methods.most_common(6)],
            "response_codes": [{"name": key, "count": value} for key, value in codes.most_common(6)],
            "request_examples": [pkt.get("summary", "") for pkt in requests[:5]],
            "response_examples": [pkt.get("summary", "") for pkt in responses[:5]],
        }

    def _risk_reasons(self, patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        weights = {"high": 5, "medium": 3, "low": 1}
        reasons = []
        for pattern in patterns or []:
            severity = str(pattern.get("severity", "low")).lower()
            reasons.append(
                {
                    "severity": severity,
                    "points": weights.get(severity, 1),
                    "type": pattern.get("type", ""),
                    "message": pattern.get("message", ""),
                    "evidence": (pattern.get("evidence") or [])[:3],
                }
            )
        return reasons

    def _flow_narrative(self, flow: Dict[str, Any], patterns: List[Dict[str, Any]]) -> str:
        proto = str(flow.get("protocol") or "UNKNOWN").upper()
        client = str(flow.get("client") or "?")
        server = str(flow.get("server") or "?")
        packets = int(flow.get("packet_count") or 0)
        duration = self._duration_seconds(flow.get("packets") or [])
        risk = self._risk_score(patterns or [])
        verbs = Counter(
            pkt.get("fields", {}).get("http.request_method", "")
            for pkt in flow.get("requests", [])
            if pkt.get("fields", {}).get("http.request_method")
        )
        sni = sorted(
            {
                pkt.get("fields", {}).get("tls.sni", "")
                for pkt in flow.get("packets", [])
                if pkt.get("fields", {}).get("tls.sni")
            }
        )
        dns = sorted(
            {
                pkt.get("fields", {}).get("dns.qname", "")
                for pkt in flow.get("packets", [])
                if pkt.get("fields", {}).get("dns.qname")
            }
        )
        extras = []
        if verbs:
            extras.append("HTTP " + ", ".join(f"{k}×{v}" for k, v in verbs.most_common(3)))
        if sni:
            extras.append("SNI " + ", ".join(sni[:3]))
        if dns:
            extras.append("DNS " + ", ".join(dns[:3]))
        if patterns:
            extras.append(f"{len(patterns)} finding(s)")
        extra = " | " + " | ".join(extras) if extras else ""
        return f"{proto} {client} -> {server}, {packets} packet(s) over {duration}s, risk {risk}{extra}."

    def _protocol_views(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        packets = flow.get("packets", []) or []
        http_requests = []
        http_responses = []
        dns_queries = Counter()
        dns_rcodes = Counter()
        tls_sni = Counter()
        tls_ja3 = Counter()
        tls_cert_issuer = Counter()
        tls_cert_subject = Counter()
        endpoints = Counter()
        for pkt in packets:
            fields = pkt.get("fields") or {}
            src = str(pkt.get("src") or "")
            dst = str(pkt.get("dst") or "")
            if src and dst:
                endpoints[f"{src} -> {dst}"] += 1
            method = fields.get("http.request_method")
            uri = fields.get("http.request_uri")
            if method or uri:
                http_requests.append(
                    {
                        "packet": pkt.get("number"),
                        "method": method or "",
                        "uri": uri or "",
                        "host": fields.get("http.host") or fields.get("raw.host") or "",
                        "user_agent": fields.get("raw.user_agent", ""),
                    }
                )
            if fields.get("http.response_code"):
                http_responses.append(
                    {
                        "packet": pkt.get("number"),
                        "code": fields.get("http.response_code", ""),
                        "phrase": fields.get("http.response_phrase", ""),
                    }
                )
            if fields.get("dns.qname"):
                dns_queries[str(fields.get("dns.qname"))] += 1
            if fields.get("dns.rcode"):
                dns_rcodes[str(fields.get("dns.rcode"))] += 1
            if fields.get("tls.sni"):
                tls_sni[str(fields.get("tls.sni"))] += 1
            if fields.get("tls.ja3_md5"):
                tls_ja3[str(fields.get("tls.ja3_md5"))] += 1
            if fields.get("tls.cert.issuer"):
                tls_cert_issuer[str(fields.get("tls.cert.issuer"))] += 1
            if fields.get("tls.cert.subject"):
                tls_cert_subject[str(fields.get("tls.cert.subject"))] += 1
        return {
            "http": {
                "requests": http_requests[:80],
                "responses": http_responses[:80],
                "methods": Counter(item["method"] for item in http_requests if item["method"]).most_common(12),
                "status_codes": Counter(item["code"] for item in http_responses if item["code"]).most_common(12),
            },
            "dns": {
                "queries": [{"name": k, "count": v} for k, v in dns_queries.most_common(40)],
                "rcodes": [{"rcode": k, "count": v} for k, v in dns_rcodes.most_common(12)],
            },
            "tls": {
                "sni": [{"name": k, "count": v} for k, v in tls_sni.most_common(20)],
                "ja3": [{"hash": k, "count": v} for k, v in tls_ja3.most_common(20)],
                "cert_issuer": [{"name": k, "count": v} for k, v in tls_cert_issuer.most_common(20)],
                "cert_subject": [{"name": k, "count": v} for k, v in tls_cert_subject.most_common(20)],
            },
            "endpoints": [{"edge": k, "count": v} for k, v in endpoints.most_common(40)],
        }

    def _extract_iocs_from_flow(self, flow: Dict[str, Any]) -> Dict[str, List[str]]:
        texts = [flow.get("client", ""), flow.get("server", "")]
        for pkt in flow.get("packets", []) or []:
            texts.extend([pkt.get("summary", ""), pkt.get("src", ""), pkt.get("dst", ""), pkt.get("payload_excerpt", "")])
            for key, value in (pkt.get("fields") or {}).items():
                texts.append(f"{key}={value}")
        return self._extract_iocs_from_texts(texts)

    def _extract_iocs_from_texts(self, texts: List[str]) -> Dict[str, List[str]]:
        buckets = {"ips": set(), "domains": set(), "urls": set(), "emails": set(), "hashes": set()}
        blob = "\n".join(str(t or "") for t in texts)
        for url in self.URL_RE.findall(blob):
            buckets["urls"].add(url.rstrip(".,);]"))
        for email in self.EMAIL_RE.findall(blob):
            buckets["emails"].add(email.lower())
        for h in self.HASH_RE.findall(blob):
            buckets["hashes"].add(h.lower())
        for ip in self.IPV4_RE.findall(blob):
            buckets["ips"].add(ip)
        for domain in self.DOMAIN_RE.findall(blob):
            d = domain.rstrip(".").lower()
            if d.startswith("http") or d.replace(".", "").isdigit():
                continue
            buckets["domains"].add(d)
        for ip in list(buckets["ips"]):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.is_unspecified or addr.is_multicast:
                buckets["ips"].discard(ip)
        return {key: sorted(values)[:200] for key, values in buckets.items()}

    def _merge_iocs(self, ioc_maps: List[Dict[str, List[str]]]) -> Dict[str, List[str]]:
        merged = {"ips": set(), "domains": set(), "urls": set(), "emails": set(), "hashes": set()}
        for item in ioc_maps or []:
            for key in merged:
                for value in (item or {}).get(key, []) or []:
                    merged[key].add(str(value))
        return {key: sorted(values)[:500] for key, values in merged.items()}

    def _endpoint_map(self, flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        nodes: Dict[str, Dict[str, Any]] = {}
        edges: Dict[str, Dict[str, Any]] = {}
        for flow in flows or []:
            client = str(flow.get("client") or "")
            server = str(flow.get("server") or "")
            chost, _ = self._parse_endpoint(client)
            shost, _ = self._parse_endpoint(server)
            if not chost or not shost:
                continue
            for host, role in ((chost, "client"), (shost, "server")):
                node = nodes.setdefault(host, {"id": host, "role": role, "flows": 0, "risk_score": 0, "internal": self._is_private_ip(host)})
                node["flows"] += 1
                node["risk_score"] += int(flow.get("risk_score") or 0)
            key = f"{chost}->{shost}"
            edge = edges.setdefault(
                key,
                {
                    "source": chost,
                    "target": shost,
                    "flows": 0,
                    "packets": 0,
                    "protocols": set(),
                    "risk_score": 0,
                },
            )
            edge["flows"] += 1
            edge["packets"] += int(flow.get("packet_count") or 0)
            edge["risk_score"] += int(flow.get("risk_score") or 0)
            edge["protocols"].add(str(flow.get("protocol") or "UNKNOWN").upper())
        clean_edges = []
        for edge in edges.values():
            row = dict(edge)
            row["protocols"] = sorted(edge["protocols"])
            clean_edges.append(row)
        clean_edges.sort(key=lambda x: (x["risk_score"], x["packets"]), reverse=True)
        return {"nodes": list(nodes.values())[:200], "edges": clean_edges[:300]}

    def _is_private_ip(self, host: str) -> bool:
        try:
            return bool(ipaddress.ip_address(host).is_private)
        except ValueError:
            return False

    def _merge_field_summary(self, packets: List[Dict[str, Any]]) -> Dict[str, str]:
        merged: Dict[str, str] = {}
        for pkt in packets[:20]:
            for key, value in pkt.get("fields", {}).items():
                if key not in merged and value:
                    merged[key] = str(value)[:300]
        return merged

    def _framework_actions(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        actions: List[Dict[str, Any]] = []
        protocol = str(flow.get("protocol", "")).upper()
        target = flow.get("server", "")
        host, _, port = target.partition(":")
        port_i = int(port) if str(port).isdigit() else 0

        def _launch(module: str, command: str) -> Dict[str, Any]:
            return {
                "kind": "kittysploit_console",
                "prefill": command,
                "deeplink": f"kittysploit://module?path={module}&target={host}&port={port_i}",
            }

        if protocol in ("HTTP", "HTTP2"):
            cmd_a = f"use auxiliary/scanner/http/api_fuzzer; set target {host}; set port {port or 80}"
            actions.append(
                {
                    "title": "Fuzz HTTP API surface",
                    "module": "auxiliary/scanner/http/api_fuzzer",
                    "command": cmd_a,
                    "launch": _launch("auxiliary/scanner/http/api_fuzzer", cmd_a),
                }
            )
            cmd_b = f"use auxiliary/scanner/http/crawler; set target {host}; set port {port or 80}"
            actions.append(
                {
                    "title": "Crawl related endpoints",
                    "module": "auxiliary/scanner/http/crawler",
                    "command": cmd_b,
                    "launch": _launch("auxiliary/scanner/http/crawler", cmd_b),
                }
            )
            if any("login" in str(pkt.get("summary", "")).lower() for pkt in flow.get("requests", [])[:10]):
                cmd_c = f"use auxiliary/scanner/http/login/admin_login_bruteforce; set target {host}; set port {port or 80}"
                actions.append(
                    {
                        "title": "Probe login behavior",
                        "module": "auxiliary/scanner/http/login/admin_login_bruteforce",
                        "command": cmd_c,
                        "launch": _launch("auxiliary/scanner/http/login/admin_login_bruteforce", cmd_c),
                    }
                )
        elif protocol == "DNS":
            cmd = f"use auxiliary/osint/domain_dns; set target {host or target}"
            actions.append(
                {
                    "title": "Resolve and pivot on DNS records",
                    "module": "auxiliary/osint/domain_dns",
                    "command": cmd,
                    "launch": _launch("auxiliary/osint/domain_dns", cmd),
                }
            )
        elif protocol == "FTP":
            cmd = f"use auxiliary/scanner/ftp/ftp_enum; set target {host}; set port {port or 21}"
            actions.append(
                {
                    "title": "Enumerate exposed FTP service",
                    "module": "auxiliary/scanner/ftp/ftp_enum",
                    "command": cmd,
                    "launch": _launch("auxiliary/scanner/ftp/ftp_enum", cmd),
                }
            )
        elif protocol == "MQTT":
            cmd = f"use auxiliary/scanner/mqtt/mqtt_bruteforce; set target {host}; set port {port or 1883}"
            actions.append(
                {
                    "title": "Enumerate MQTT topics",
                    "module": "auxiliary/scanner/mqtt/mqtt_bruteforce",
                    "command": cmd,
                    "launch": _launch("auxiliary/scanner/mqtt/mqtt_bruteforce", cmd),
                }
            )
        elif protocol == "SIP":
            cmd = f"use auxiliary/scanner/sip/options; set target {host}; set port {port or 5060}"
            actions.append(
                {
                    "title": "Probe SIP endpoints and auth",
                    "module": "auxiliary/scanner/sip/options",
                    "command": cmd,
                    "launch": _launch("auxiliary/scanner/sip/options", cmd),
                }
            )
        elif protocol == "TLS":
            cmd = f"use auxiliary/scanner/ssl/ssl_version; set target {host}; set port {port or 443}"
            actions.append(
                {
                    "title": "Inspect TLS surface",
                    "module": "auxiliary/scanner/ssl/ssl_version",
                    "command": cmd,
                    "launch": _launch("auxiliary/scanner/ssl/ssl_version", cmd),
                }
            )
        return actions[:4]

    def _packet_to_record(self, packet, include_raw: bool) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        src_ip, dst_ip = self._get_ips(packet)
        if not src_ip or not dst_ip:
            return None, None

        transport = self._get_transport(packet)
        if not transport:
            return None, None

        src_port = self._get_port(packet, "sport")
        dst_port = self._get_port(packet, "dport")
        proto_guess = self._infer_protocol_confidence(packet, "", src_port, dst_port)
        protocol = proto_guess.get("protocol", "UNKNOWN")
        fields = self._extract_interesting_fields(packet)
        refined = protocol_intel.refine_protocol_label(packet, protocol, src_port, dst_port)
        if refined and refined != protocol:
            proto_guess["reasons"] = list(proto_guess.get("reasons") or []) + [f"Refined from {protocol} to {refined} using protocol intelligence hints."]
            protocol = refined
        fields = protocol_intel.enrich_packet_fields(packet, fields, protocol)
        blob = self._normalize_text_blob(fields)
        summary = self._build_packet_summary(protocol, fields, src_ip, src_port, dst_ip, dst_port)

        info = {
            "number": self._safe_int(getattr(packet, "number", 0), 0),
            "timestamp": self._packet_timestamp(packet),
            "timestamp_epoch": self._packet_timestamp_epoch(packet),
            "protocol": protocol,
            "transport": transport,
            "src": f"{src_ip}:{src_port}",
            "dst": f"{dst_ip}:{dst_port}",
            "src_port": src_port,
            "dst_port": dst_port,
            "length": len(bytes(packet)) if packet is not None else 0,
            "direction": self._infer_direction(protocol, src_port, dst_port, fields),
            "fields": fields,
            "summary": summary,
            "signature": self._build_request_signature(protocol, fields, blob),
            "auth_hint": bool(self.AUTH_HINT_RE.search(blob)),
            "nonce_hint": bool(self.NONCE_HINT_RE.search(blob)),
            "payload_excerpt": blob[:240] if include_raw else "",
            "protocol_confidence": int(proto_guess.get("confidence", 0) or 0),
            "protocol_evidence": list(proto_guess.get("reasons") or [])[:8],
        }
        flow_key = self._canonical_flow_key(transport, src_ip, src_port, dst_ip, dst_port)
        return flow_key, info

    def _extract_interesting_fields(self, packet) -> Dict[str, str]:
        fields: Dict[str, str] = {}
        raw_bytes = self._raw_bytes(packet)
        raw_text = raw_bytes.decode("utf-8", errors="ignore") if raw_bytes else ""

        if raw_text:
            req_match = self.HTTP_REQ_LINE_RE.search(raw_bytes)
            if req_match:
                method = req_match.group(1).decode("utf-8", errors="ignore").upper()
                uri = req_match.group(2).decode("utf-8", errors="ignore")
                fields["http.request_method"] = method
                fields["http.request_uri"] = uri
                host_match = self.HTTP_HOST_RE.search(raw_bytes)
                if host_match:
                    fields["http.host"] = host_match.group(1).decode("utf-8", errors="ignore").strip()
            status_match = self.HTTP_STATUS_RE.search(raw_bytes)
            if status_match:
                fields["http.response_code"] = status_match.group(1).decode("utf-8", errors="ignore")
                fields["http.response_phrase"] = status_match.group(2).decode("utf-8", errors="ignore").strip()

            for line in raw_text.splitlines()[:60]:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                normalized_key = key.strip().lower().replace("-", "_")
                cleaned = value.strip()
                if normalized_key and cleaned:
                    fields[f"raw.{normalized_key}"] = cleaned[:300]

        summary_text = self._scapy_text(packet)
        if summary_text and "dns" in summary_text.lower():
            fields["proto.summary"] = summary_text[:300]
        return fields

    def _detect_patterns(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        patterns: List[Dict[str, Any]] = []
        for pkt in flow["packets"]:
            clear_fields = self._find_cleartext_credentials(pkt["fields"])
            if clear_fields:
                patterns.append(self._pattern(flow, "cleartext_credentials_or_tokens", "high", f"Sensitive values observed in cleartext on packet #{pkt['number']}", clear_fields, pkt["number"]))

        if flow["auth_related_packets"] and not self._flow_has_authenticator(flow):
            evidence = [pkt["summary"] for pkt in flow["requests"][:3]]
            patterns.append(self._pattern(flow, "missing_authentication_pattern", "high", "Flow appears auth-related but no explicit authenticator, token, cookie, or challenge was found", evidence))

        for anomaly in self._detect_length_anomalies(flow):
            patterns.append(self._pattern(flow, "suspicious_field_lengths_or_anomalies", anomaly["severity"], anomaly["message"], anomaly["evidence"], anomaly.get("packet_number")))

        replay = self._detect_replayable_requests(flow)
        if replay:
            patterns.append(self._pattern(flow, "replayable_requests", replay["severity"], replay["message"], replay["evidence"]))

        for hit in self._detect_sensitive_commands(flow):
            patterns.append(self._pattern(flow, "sensitive_commands_or_endpoints", hit["severity"], hit["message"], hit["evidence"], hit.get("packet_number")))
        return patterns

    def _find_cleartext_credentials(self, fields: Dict[str, str]) -> List[str]:
        findings = []
        for key, value in fields.items():
            if self.CREDENTIAL_FIELD_RE.search(key) and value and len(value) >= 3 and not value.startswith("\\x"):
                findings.append(f"{key}={value[:80]}")
            elif self.CREDENTIAL_FIELD_RE.search(value) and self.CLEAR_VALUE_RE.search(value):
                findings.append(f"{key}={value[:80]}")
        return findings[:5]

    def _flow_has_authenticator(self, flow: Dict[str, Any]) -> bool:
        for pkt in flow["packets"]:
            joined = " ".join(f"{k}={v}" for k, v in pkt["fields"].items())
            if re.search(r"(authorization|cookie|set-cookie|token|apikey|api_key|sessionid|jwt|digest|basic)", joined, re.I):
                return True
        return False

    def _detect_length_anomalies(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        anomalies = []
        avg = flow.get("avg_packet_size", 0)
        std = flow.get("std_packet_size", 0)
        for pkt in flow["packets"]:
            evidence = []
            if avg and std and pkt["length"] > avg + max(48, 2.5 * std):
                evidence.append(f"packet_length={pkt['length']} avg={avg:.1f} std={std:.1f}")
            for key, value in pkt["fields"].items():
                value_len = len(str(value))
                if value_len > 256 and any(token in key.lower() for token in ("param", "value", "path", "uri", "data", "command")):
                    evidence.append(f"{key} length={value_len}")
            if evidence:
                anomalies.append({"severity": "medium", "message": f"Packet #{pkt['number']} contains unusually large fields or payload length", "evidence": evidence[:5], "packet_number": pkt["number"]})
        return anomalies[:8]

    def _detect_replayable_requests(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        duplicates = [(sig, count) for sig, count in flow["unique_request_signatures"].items() if sig and count > 1]
        if not duplicates or flow["nonce_related_packets"] > 0:
            return None
        return {
            "severity": "medium",
            "message": "Repeated request signatures were observed without obvious nonce/randomness fields",
            "evidence": [f"{sig} repeated {count} times" for sig, count in duplicates[:5]],
        }

    def _detect_sensitive_commands(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        for pkt in flow["requests"]:
            blob = self._normalize_text_blob(pkt["fields"])
            hits = sorted({kw for kw in self.sensitive_keywords if kw in blob.lower()})
            if self.SENSITIVE_ENDPOINT_RE.search(blob) or hits:
                findings.append({"severity": "medium" if hits else "low", "message": f"Sensitive endpoint/command semantics observed in packet #{pkt['number']}", "evidence": hits[:5] or [pkt["summary"]], "packet_number": pkt["number"]})
        return findings[:8]

    def _build_suggestions(self, flow: Dict[str, Any], patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        suggestions = []
        seen = set()
        for pattern in patterns:
            ptype = pattern["type"]
            if ptype in seen:
                continue
            seen.add(ptype)
            if ptype == "cleartext_credentials_or_tokens":
                suggestions.append(self._suggestion(flow, ptype, ["credential disclosure", "session hijacking", "insecure transport"], ["replay captured credentials", "try token reuse across endpoints", "force downgrade to plaintext if possible"], ["verify whether TLS is expected", "check token scope and expiry", "look for privilege escalation paths using the leaked secret"]))
            elif ptype == "missing_authentication_pattern":
                suggestions.append(self._suggestion(flow, ptype, ["authentication bypass", "authorization weakness"], ["send the same request unauthenticated", "mutate role or user identifiers", "compare responses with and without session metadata"], ["enumerate adjacent endpoints", "check whether the server trusts client-side identity fields", "test for IDOR or implicit trust"]))
            elif ptype == "suspicious_field_lengths_or_anomalies":
                suggestions.append(self._suggestion(flow, ptype, ["parser confusion", "input validation weakness", "memory corruption in non-hardened services"], ["fuzz oversized fields", "mutate field boundaries", "inject malformed encodings and chunk sizes"], ["identify the server-side parser implementation", "test boundary lengths around the anomalous value", "monitor for crashes or desync"]))
            elif ptype == "replayable_requests":
                suggestions.append(self._suggestion(flow, ptype, ["replay attack", "idempotency abuse", "business logic duplication"], ["re-send identical requests", "replay from a different source or IP", "reorder captured requests to test state handling"], ["check whether the server issues per-request tokens", "measure whether the action is executed multiple times", "combine replay with race-condition testing"]))
            elif ptype == "sensitive_commands_or_endpoints":
                suggestions.append(self._suggestion(flow, ptype, ["dangerous functionality exposure", "command injection", "administrative surface expansion"], ["fuzz parameters on the sensitive endpoint", "test authz bypass on admin or debug paths", "mutate verbs and content types"], ["map related commands and endpoints", "compare behavior across privilege levels", "check logging and error leakage for backend hints"]))
        return suggestions

    def _build_timeline(self, requests: List[Dict[str, Any]], responses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        timeline = []
        response_idx = 0
        for req in requests:
            matched = responses[response_idx] if response_idx < len(responses) else None
            if matched is not None:
                response_idx += 1
            timeline.append({
                "request_packet": req["number"],
                "request": req["summary"],
                "response_packet": matched["number"] if matched else None,
                "response": matched["summary"] if matched else None,
            })
        return timeline[:20]

    def _build_http_pair_timeline(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        ordered = sorted(packets, key=lambda p: (float(p.get("timestamp_epoch", 0) or 0.0), int(p.get("number") or 0)))
        timeline: List[Dict[str, Any]] = []
        pending: Optional[Dict[str, Any]] = None
        for pkt in ordered:
            fields = pkt.get("fields") or {}
            if fields.get("http.request_method") or fields.get("http.request_uri"):
                if pending:
                    timeline.append(
                        {
                            "request_packet": pending["number"],
                            "request": pending["summary"],
                            "response_packet": None,
                            "response": None,
                        }
                    )
                pending = pkt
            elif fields.get("http.response_code") and pending:
                timeline.append(
                    {
                        "request_packet": pending["number"],
                        "request": pending["summary"],
                        "response_packet": pkt["number"],
                        "response": pkt["summary"],
                    }
                )
                pending = None
        if pending:
            timeline.append(
                {
                    "request_packet": pending["number"],
                    "request": pending["summary"],
                    "response_packet": None,
                    "response": None,
                }
            )
        return timeline[:30]

    def _build_flow_timeline(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        proto = str(flow.get("protocol", "") or "").upper()
        if proto in ("HTTP", "HTTP2"):
            return self._build_http_pair_timeline(flow.get("packets", []) or [])
        return self._build_timeline(flow.get("requests", []) or [], flow.get("responses", []) or [])

    def _dominant_protocol_from_packets(self, flow: Dict[str, Any]) -> str:
        order = [
            "HTTP2",
            "HTTP",
            "TLS",
            "KERBEROS",
            "SMB",
            "MQTT",
            "DNS",
            "QUIC",
            "FTP",
            "SIP",
            "SSH",
            "TCP",
            "UDP",
            "UNKNOWN",
        ]
        packets = flow.get("packets") or []
        if not packets:
            return str(flow.get("protocol") or "UNKNOWN").upper()
        counts = Counter(str(p.get("protocol") or "UNKNOWN").upper() for p in packets)
        best = str(flow.get("protocol") or "UNKNOWN").upper()
        best_key: Tuple[int, int] = (99, 0)
        for pr, cnt in counts.items():
            try:
                idx = order.index(pr)
            except ValueError:
                idx = 70
            key = (idx, -cnt)
            if key < best_key:
                best_key = key
                best = pr
        return best

    def _build_global_timeline(self, flows: List[Dict[str, Any]], limit: int = 500) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        for flow in flows or []:
            fid = str(flow.get("id", "") or "")
            proto = str(flow.get("protocol", "") or "")
            pkts = (
                flow.get("packets")
                or flow.get("_replay_packets_all")
                or flow.get("replay_packets")
                or []
            )
            for pkt in pkts:
                summary = str(pkt.get("summary", "") or "")
                lower = summary.lower()
                if any(token in lower for token in ("login", "auth", "token", "password")):
                    event_kind = "auth"
                elif any(token in lower for token in ("error", "fail", "denied", "forbidden", "unauthorized")):
                    event_kind = "error"
                elif any(token in lower for token in ("retry", "retrans", "again", "timeout")):
                    event_kind = "retry"
                elif any(token in lower for token in ("upload", "download", "exfil", "dump", "archive")):
                    event_kind = "exfil_candidate"
                else:
                    event_kind = "normal"
                events.append(
                    {
                        "t": float(pkt.get("timestamp_epoch", 0) or 0.0),
                        "timestamp": pkt.get("timestamp", ""),
                        "flow_id": fid,
                        "protocol": proto,
                        "summary": summary,
                        "packet_number": pkt.get("number"),
                        "event_kind": event_kind,
                    }
                )
        events.sort(key=lambda x: (x["t"], x.get("packet_number") or 0))
        return events[:limit]

    def bpf_display_filter_help(self) -> Dict[str, str]:
        return {
            "bpf": (
                "libpcap capture filter (tcpdump syntax), applied live on the interface and offline "
                "when `bpf_filter` is provided. Examples: `tcp port 443`, `host 10.0.0.5 and udp port 53`."
            ),
            "display_filter": (
                "KittyProtocol text filter: case-insensitive substring on Scapy summary and inferred protocol "
                "inferred (this is not a full Wireshark display filter)."
            ),
        }

    def search_payloads(self, query: str, limit: int = 80) -> Dict[str, Any]:
        if not self._payload_index:
            return {"error": "No full-text index for this session (enable enable_fts during analysis).", "hits": []}
        return {"session_id": self._session_id, "hits": self._payload_index.search(query, limit=limit)}

    @staticmethod
    def compare_pcaps(
        pcap_a: str,
        pcap_b: str,
        display_filter: Optional[str] = None,
        protocol_filter: Optional[str] = None,
        max_packets: Optional[int] = 2000,
        bpf_filter_a: Optional[str] = None,
        bpf_filter_b: Optional[str] = None,
        include_raw: bool = False,
        enable_fts: bool = False,
    ) -> Dict[str, Any]:
        left = KittyProtocolAnalyzer()
        right = KittyProtocolAnalyzer()
        ra = left.analyze_file(
            pcap_a,
            display_filter=display_filter,
            protocol_filter=protocol_filter,
            max_packets=max_packets,
            include_raw=include_raw,
            bpf_filter=bpf_filter_a,
            enable_fts=enable_fts,
        )
        if "error" in ra:
            return {"error": ra["error"], "which": "a"}
        rb = right.analyze_file(
            pcap_b,
            display_filter=display_filter,
            protocol_filter=protocol_filter,
            max_packets=max_packets,
            include_raw=include_raw,
            bpf_filter=bpf_filter_b,
            enable_fts=enable_fts,
        )
        if "error" in rb:
            return {"error": rb["error"], "which": "b"}
        return {
            "compare": compare_summaries(ra.get("flows", []), rb.get("flows", [])),
            "summary_a": {"flow_count": ra.get("flow_count"), "session_id": ra.get("session_id"), "pcap": ra.get("pcap")},
            "summary_b": {"flow_count": rb.get("flow_count"), "session_id": rb.get("session_id"), "pcap": rb.get("pcap")},
        }

    def export_flow_subset_json(
        self,
        flow_id: str,
        time_start: Optional[float] = None,
        time_end: Optional[float] = None,
    ) -> Dict[str, Any]:
        detail = self._analysis_cache.get(str(flow_id or "").strip())
        if not detail:
            return {"error": "Flows not found"}
        t0 = float(time_start) if time_start is not None else None
        t1 = float(time_end) if time_end is not None else None
        pkts = list(detail.get("_replay_packets_all") or detail.get("replay_packets") or [])
        if t0 is not None or t1 is not None:
            filtered = []
            for pkt in pkts:
                ts = float(pkt.get("timestamp_epoch", 0) or 0.0)
                if t0 is not None and ts < t0:
                    continue
                if t1 is not None and ts > t1:
                    continue
                filtered.append(pkt)
            pkts = filtered
        return {
            "flow_id": flow_id,
            "time_start": t0,
            "time_end": t1,
            "packet_count": len(pkts),
            "packets": pkts,
            "provenance": self._last_result.get("provenance"),
            "session_id": self._last_result.get("session_id") or self._session_id,
        }

    @staticmethod
    def _parse_endpoint(endpoint: str) -> Tuple[str, int]:
        text = str(endpoint or "").strip()
        host, _, port = text.rpartition(":")
        if not host and text.count(":") > 1:
            if text.startswith("[") and "]:" in text:
                inner, _, prt = text.rpartition(":")
                host = inner.strip("[]")
                try:
                    return host, int(prt)
                except ValueError:
                    return text, 0
        try:
            return host or text, int(port) if port else 0
        except ValueError:
            return host or text, 0

    def export_flow_pcap_bytes(self, flow_id: str) -> Tuple[bytes, str]:
        detail = self._analysis_cache.get(str(flow_id or "").strip())
        if not detail:
            raise ValueError("Flow not found")
        path = self._last_source_pcap
        if not path or not os.path.isfile(path):
            raise ValueError("No source PCAP path for this analysis session")
        c_ip, c_port = self._parse_endpoint(str(detail.get("client", "")))
        s_ip, s_port = self._parse_endpoint(str(detail.get("server", "")))
        matched: List[Any] = []
        try:
            from scapy.utils import PcapReader
            from scapy.all import wrpcap

            with PcapReader(path) as reader:
                for pkt in reader:
                    if self._packet_matches_flow_endpoints(pkt, c_ip, c_port, s_ip, s_port):
                        matched.append(pkt)
            buf = BytesIO()
            wrpcap(buf, matched)
            safe = self._slugify(flow_id)[:40] or "flow"
            return buf.getvalue(), f"{safe}.pcap"
        except Exception as exc:
            raise RuntimeError(f"PCAP export failed: {exc}") from exc

    def _render_console(self, flows: List[Dict[str, Any]], patterns: List[Dict[str, Any]], suggestions: List[Dict[str, Any]]) -> None:
        if flows:
            print_info("")
            print_table(["Proto", "Client", "Server", "Packets", "Patterns"], [[flow["protocol"], flow["client"], flow["server"], flow["packet_count"], len(flow["patterns"])] for flow in flows[:20]], max_width=140)
        if patterns:
            print_info("")
            print_table(["Severity", "Pattern", "Flow", "Message"], [[item["severity"].upper(), item["type"], item["flow_id"], item["message"][:72]] for item in patterns[:20]], max_width=160)
        for suggestion in suggestions[:10]:
            print_info("")
            print_status(f"[{suggestion['pattern']}] Possible vulns: {', '.join(suggestion['possible_vulnerabilities'])}")
            print_info(f"Attack ideas: {', '.join(suggestion['attack_ideas'])}")
            print_info(f"Next steps: {', '.join(suggestion['next_steps'])}")
        if flows or patterns:
            print_success(f"Analysis complete: {len(flows)} flow(s), {len(patterns)} pattern(s), {len(suggestions)} suggestion set(s)")
        else:
            print_warning("No flows or patterns extracted from the capture")

    def _pattern(self, flow: Dict[str, Any], pattern_type: str, severity: str, message: str, evidence: Optional[List[str]] = None, packet_number: Optional[int] = None) -> Dict[str, Any]:
        row: Dict[str, Any] = {
            "flow_id": flow["id"],
            "protocol": flow["protocol"],
            "type": pattern_type,
            "severity": severity,
            "message": message,
            "packet_number": packet_number,
            "evidence": evidence or [],
        }
        mods = modules_for_observation(pattern_type)
        if mods:
            row["observation_modules"] = mods
        return row

    def _suggestion(self, flow: Dict[str, Any], pattern: str, vulns: List[str], attacks: List[str], steps: List[str]) -> Dict[str, Any]:
        return {
            "flow_id": flow["id"],
            "protocol": flow["protocol"],
            "pattern": pattern,
            "possible_vulnerabilities": vulns,
            "attack_ideas": attacks,
            "next_steps": steps,
            "playbook": get_playbook(pattern),
        }

    def _guess_client_server(self, packet_info: Dict[str, Any]) -> Tuple[str, str]:
        if packet_info["dst_port"] < packet_info["src_port"] or packet_info["dst_port"] in (80, 443, 53, 21, 1883, 5060):
            return packet_info["src"], packet_info["dst"]
        return packet_info["dst"], packet_info["src"]

    def _canonical_flow_key(self, transport: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
        """Transport-only key so one TCP session aggregates TLS/HTTP layers."""
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        left, right = (a, b) if a <= b else (b, a)
        return f"{transport}|{left[0]}:{left[1]}|{right[0]}:{right[1]}"

    def _infer_direction(self, protocol: str, src_port: int, dst_port: int, fields: Dict[str, str]) -> str:
        if protocol in ("HTTP", "HTTP2"):
            if "http.request_method" in fields or "http.request_uri" in fields:
                return "request"
            if "http.response_code" in fields:
                return "response"
            if fields.get("tls.sni"):
                return "request"
        if dst_port in (80, 443, 8080, 8000, 8888, 53, 21, 1883, 5060):
            return "request"
        if src_port in (80, 443, 8080, 8000, 8888, 53, 21, 1883, 5060):
            return "response"
        return "request"

    def _build_request_signature(self, protocol: str, fields: Dict[str, str], blob: str) -> str:
        if protocol == "HTTP":
            method = fields.get("http.request_method", "")
            uri = fields.get("http.request_uri") or fields.get("http.request_full_uri") or ""
            if method or uri:
                return f"{method} {uri}".strip()
        chunks = [token for token in self.TEXT_SPLIT_RE.split(blob) if token][:4]
        return " ".join(chunks)[:120]

    def _build_packet_summary(self, protocol: str, fields: Dict[str, str], src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
        if protocol in ("HTTP", "HTTP2"):
            method = fields.get("http.request_method", "")
            uri = fields.get("http.request_uri") or fields.get("http.request_full_uri") or ""
            code = fields.get("http.response_code", "")
            if method or uri:
                return f"{method} {uri}".strip()
            if code:
                return f"{protocol} {code}"
            if fields.get("tls.sni"):
                return f"{protocol} SNI {fields.get('tls.sni', '')[:80]}"
        if protocol == "TLS" and fields.get("tls.sni"):
            return f"TLS ClientHello SNI={fields.get('tls.sni', '')[:80]}"
        if protocol == "SSH":
            banner = fields.get("raw.ssh-2.0") or fields.get("raw.ssh-1.99")
            if banner:
                return f"SSH banner {str(banner)[:100]}"
            return f"SSH {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        if fields.get("dns.qname"):
            return f"DNS {fields.get('dns.qname', '')[:120]}"
        return f"{protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

    def _normalize_text_blob(self, fields: Dict[str, str]) -> str:
        blob = " ".join(f"{k}={v}" for k, v in fields.items())
        return blob[:4000]

    def _can_import_scapy(self) -> bool:
        try:
            import scapy.all  # noqa: F401
            return True
        except Exception:
            return False

    def _get_ips(self, packet) -> Tuple[Optional[str], Optional[str]]:
        if packet.haslayer("IP"):
            layer = packet["IP"]
            return str(layer.src), str(layer.dst)
        if packet.haslayer("IPv6"):
            layer = packet["IPv6"]
            return str(layer.src), str(layer.dst)
        # Fallback: check if we have Dot1Q or SLL or other wrappers that might hide IP
        for layer_name in ["IP", "IPv6"]:
            try:
                l = packet.getlayer(layer_name)
                if l:
                    return str(l.src), str(l.dst)
            except Exception:
                pass
        # Final fallback for non-IP packets that we still want to track (e.g. ARP)
        if packet.haslayer("ARP"):
            return str(packet["ARP"].psrc), str(packet["ARP"].pdst)
        return None, None

    def _get_transport(self, packet) -> str:
        if packet.haslayer("TCP"):
            return "TCP"
        if packet.haslayer("UDP"):
            return "UDP"
        # Fallback for ICMP or other protocols if needed
        if packet.haslayer("ICMP") or packet.haslayer("ICMPv6"):
            return "ICMP"
        # Check IP protocol field if available
        if packet.haslayer("IP"):
            proto_num = packet["IP"].proto
            if proto_num == 6: return "TCP"
            if proto_num == 17: return "UDP"
            if proto_num == 1: return "ICMP"
        return ""

    def _get_port(self, packet, direction: str) -> int:
        try:
            if packet.haslayer("TCP"):
                tcp = packet["TCP"]
                return int(getattr(tcp, direction, 0) or 0)
            if packet.haslayer("UDP"):
                udp = packet["UDP"]
                return int(getattr(udp, direction, 0) or 0)
        except Exception:
            return 0
        return 0

    def _infer_protocol_confidence(self, packet, highest_layer: str, src_port: int, dst_port: int) -> Dict[str, Any]:
        packet_layers = {layer.__name__.upper() for layer in packet.layers()}
        reasons: List[str] = []
        confidence = 20
        protocol = ""
        if "HTTP2" in packet_layers or "H2FRAME" in packet_layers:
            protocol = "HTTP2"
            confidence = 95
            reasons.append("Scapy HTTP/2 layer detected.")
        elif "HTTPREQUEST" in packet_layers or "HTTPRESPONSE" in packet_layers:
            protocol = "HTTP"
            confidence = 95
            reasons.append("Scapy HTTP request/response layer detected.")
        elif "DNS" in packet_layers:
            protocol = "DNS"
            confidence = 95
            reasons.append("Scapy DNS layer detected.")
        elif "SMB2" in packet_layers or "SMB_HEADER" in packet_layers or "SMB" in packet_layers:
            protocol = "SMB"
            confidence = 90
            reasons.append("Scapy SMB layer detected.")
        elif "KRB5" in packet_layers or "KERBEROS" in packet_layers:
            protocol = "KERBEROS"
            confidence = 90
            reasons.append("Scapy Kerberos layer detected.")
        elif "MQTT" in packet_layers:
            protocol = "MQTT"
            confidence = 90
            reasons.append("Scapy MQTT layer detected.")
        try:
            raw = self._raw_bytes(packet)
        except Exception:
            raw = b""
        if raw.startswith(b"SSH-2.0") or raw.startswith(b"SSH-1.99"):
            protocol = "SSH"
            confidence = max(confidence, 96)
            reasons.append("Raw payload starts with an SSH banner.")
        known = {
            22: "SSH",
            80: "HTTP",
            8080: "HTTP",
            8000: "HTTP",
            8888: "HTTP",
            443: "TLS",
            8443: "TLS",
            9443: "TLS",
            10443: "TLS",
            53: "DNS",
            1883: "MQTT",
            21: "FTP",
            5060: "SIP",
        }
        for port in (src_port, dst_port):
            if port in known:
                if not protocol:
                    protocol = known[port]
                    confidence = max(confidence, 72)
                reasons.append(f"Known service port hint: {port}->{known[port]}.")
        if not protocol:
            protocol = highest_layer or (next(iter(packet_layers)) if packet_layers else "UNKNOWN")
            confidence = max(confidence, 35 if protocol != "UNKNOWN" else 10)
            reasons.append("Fallback to highest available packet layer.")
        return {"protocol": protocol, "confidence": min(99, max(1, int(confidence))), "reasons": reasons[:8]}

    def _infer_protocol(self, packet, highest_layer: str, src_port: int, dst_port: int) -> str:
        return str(self._infer_protocol_confidence(packet, highest_layer, src_port, dst_port).get("protocol") or "UNKNOWN")

    def _infer_protocol_criticality(self, pattern: Dict[str, Any]) -> int:
        severity_weights = {"high": 100, "medium": 60, "low": 30}
        sev = str(pattern.get("severity", "low")).lower()
        score = severity_weights.get(sev, 20)
        score += 8 if pattern.get("packet_number") else 0
        score += min(20, len(pattern.get("evidence") or []) * 4)
        ptype = str(pattern.get("type", "")).lower()
        if "credential" in ptype or "token" in ptype:
            score += 20
        elif "replay" in ptype:
            score += 12
        return score

    def _normalize_patterns_for_display(self, patterns: List[Dict[str, Any]], flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        flows_by_id = {str(flow.get("id")): flow for flow in (flows or [])}
        grouped: Dict[str, Dict[str, Any]] = {}
        for row in patterns or []:
            flow_id = str(row.get("flow_id") or "")
            ptype = str(row.get("type") or "")
            sev = str(row.get("severity") or "low").lower()
            key = "|".join([flow_id, ptype, sev])
            base = grouped.get(key)
            if not base:
                base = dict(row)
                base["_occurrences"] = 0
                base["_criticality"] = self._infer_protocol_criticality(row)
                base["_seen_ev"] = set()
                grouped[key] = base
            base["_occurrences"] += 1
            base["_criticality"] = max(int(base.get("_criticality", 0) or 0), self._infer_protocol_criticality(row))
            for ev in (row.get("evidence") or []):
                marker = str(ev)
                if marker in base["_seen_ev"]:
                    continue
                base["_seen_ev"].add(marker)
        out: List[Dict[str, Any]] = []
        for item in grouped.values():
            flow_id = str(item.get("flow_id") or "")
            flow = flows_by_id.get(flow_id) or {}
            evidence = list(item.get("_seen_ev") or [])[:8]
            merged = {k: v for k, v in item.items() if not str(k).startswith("_")}
            merged["evidence"] = evidence
            merged["occurrences"] = int(item.get("_occurrences", 1) or 1)
            merged["criticality_score"] = int(item.get("_criticality", 0) or 0) + min(30, int(flow.get("risk_score", 0) or 0) * 4)
            merged["group_key"] = f"{flow_id}:{merged.get('type', '')}:{merged.get('severity', '')}"
            out.append(merged)
        out.sort(key=lambda x: (int(x.get("criticality_score", 0) or 0), int(x.get("occurrences", 1) or 1)), reverse=True)
        return out

    def _packet_timestamp(self, packet) -> str:
        try:
            return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(float(packet.time)))
        except Exception:
            return ""

    def _packet_timestamp_epoch(self, packet) -> float:
        try:
            return float(packet.time)
        except Exception:
            return 0.0

    def _raw_bytes(self, packet) -> bytes:
        try:
            if packet.haslayer("Raw"):
                return bytes(packet["Raw"].load)
        except Exception:
            pass
        return b""

    def _scapy_text(self, packet) -> str:
        try:
            return packet.summary()
        except Exception:
            return ""

    def _clone_and_finalize_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        cloned = {
            "id": flow["id"],
            "protocol": flow["protocol"],
            "transport": flow["transport"],
            "client": flow["client"],
            "server": flow["server"],
            "packet_count": flow["packet_count"],
            "requests": list(flow["requests"]),
            "responses": list(flow["responses"]),
            "packets": list(flow["packets"]),
            "packet_sizes": list(flow["packet_sizes"]),
            "auth_related_packets": flow["auth_related_packets"],
            "nonce_related_packets": flow["nonce_related_packets"],
        }
        self._finalize_flow(cloned)
        return cloned

    def _resolve_sniff_interface(self, iface: str) -> Tuple[str, str]:
        """Map UI pseudo-interfaces to a name Scapy can open.

        Scapy does not support Linux tcpdump/libpcap pseudo-device ``any``; passing
        ``iface='any'`` raises ``ValueError: Interface 'any' not found``. We map
        pseudo names to ``conf.iface`` (default route interface).
        """
        raw = str(iface or "").strip()
        low = raw.lower()
        pseudo = {"any", "all", "*", "auto"}
        if low not in pseudo:
            return raw, ""
        try:
            from scapy.all import conf, get_if_list

            resolved = str(getattr(conf, "iface", "") or "").strip()
            if not resolved or resolved.lower() in pseudo:
                names = [n for n in (get_if_list() or []) if n and str(n).lower() != "lo"]
                resolved = str(names[0]) if names else "lo"
            note = (
                f"'{raw}' maps to Scapy default interface '{resolved}' "
                "(tcpdump-style multi-NIC 'any' is not supported by Scapy here). "
                "Pick a specific NIC to capture all of its traffic."
            )
            return resolved, note
        except Exception as exc:
            return raw, f"Could not resolve default interface for '{raw}': {exc}"

    def _list_system_interfaces(self) -> List[str]:
        names = []
        try:
            import psutil
            names.extend(list(psutil.net_if_addrs().keys()))
        except Exception:
            pass
        try:
            names.extend([name for _, name in socket.if_nameindex()])
        except Exception:
            pass
        unique = []
        seen = set()
        for name in names:
            cleaned = str(name).strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                unique.append(cleaned)
        return unique

    def _safe_int(self, value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _duration_seconds(self, packets: List[Dict[str, Any]]) -> float:
        if len(packets) < 2:
            return 0.0
        start = float(packets[0].get("timestamp_epoch", 0.0) or 0.0)
        end = float(packets[-1].get("timestamp_epoch", 0.0) or 0.0)
        return round(max(0.0, end - start), 3)

    def _slugify(self, value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "").strip()).strip("-._")[:120]

    def _stddev(self, values: List[int]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        return math.sqrt(variance)

    def _normalize_protocol_filter(self, protocol_filter: Optional[str]) -> List[str]:
        if protocol_filter is None:
            return []
        if isinstance(protocol_filter, (list, tuple, set)):
            raw_items = [str(item) for item in protocol_filter]
        else:
            raw_items = re.split(r"[,\s;]+", str(protocol_filter))
        normalized = []
        seen = set()
        for item in raw_items:
            token = str(item).strip().upper()
            if not token or token in seen:
                continue
            seen.add(token)
            normalized.append(token)
        return normalized

    def _normalize_severity_filter(self, severity_filter: Optional[str]) -> List[str]:
        if severity_filter is None:
            return []
        if isinstance(severity_filter, (list, tuple, set)):
            raw_items = [str(item) for item in severity_filter]
        else:
            raw_items = re.split(r"[,\s;]+", str(severity_filter))
        allowed = {"high", "medium", "low"}
        normalized = []
        seen = set()
        for item in raw_items:
            token = str(item).strip().lower()
            if not token or token not in allowed or token in seen:
                continue
            seen.add(token)
            normalized.append(token)
        return normalized

    def _paginate(self, items: List[Dict[str, Any]], page: int, per_page: int) -> Dict[str, Any]:
        total = len(items or [])
        safe_per_page = max(1, min(self._safe_int(per_page, 25), 200))
        total_pages = max(1, math.ceil(total / safe_per_page))
        safe_page = max(1, min(self._safe_int(page, 1), total_pages))
        start = (safe_page - 1) * safe_per_page
        end = start + safe_per_page
        return {
            "items": list(items[start:end]),
            "meta": {
                "page": safe_page,
                "per_page": safe_per_page,
                "total": total,
                "total_pages": total_pages,
                "has_next": safe_page < total_pages,
                "has_prev": safe_page > 1,
            },
        }

    def _risk_score(self, patterns: List[Dict[str, Any]]) -> int:
        weights = {"high": 5, "medium": 3, "low": 1}
        return sum(weights.get(str(item.get("severity", "")).lower(), 1) for item in patterns or [])

    def _protocol_stats(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        stats: Dict[str, Dict[str, Any]] = {}
        for flow in flows:
            proto = str(flow.get("protocol", "UNKNOWN")).upper()
            entry = stats.setdefault(proto, {"protocol": proto, "flow_count": 0, "packet_count": 0, "pattern_count": 0, "risk_score": 0})
            entry["flow_count"] += 1
            entry["packet_count"] += int(flow.get("packet_count", 0) or 0)
            entry["pattern_count"] += len(flow.get("patterns", []) or [])
            entry["risk_score"] += int(flow.get("risk_score", 0) or 0)
        ordered = sorted(stats.values(), key=lambda row: (row["risk_score"], row["packet_count"]), reverse=True)
        return ordered
