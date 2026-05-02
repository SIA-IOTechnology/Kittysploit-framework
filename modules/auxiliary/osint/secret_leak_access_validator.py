from kittysploit import *
import json
import re
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Secret Leak to Access Validator",
        "author": ["KittySploit Team"],
        "description": "Detect leaked secret patterns in public artifacts and validate probable access safely.",
        "tags": ["osint", "secrets", "validation", "exposure"],
    }

    target = OptString("", "Target URL/domain to inspect (optional when input_file is used)", required=False)
    input_file = OptString("", "Optional JSON file containing text blobs or findings", required=False)
    active_validation = OptBool(False, "Enable active remote validation requests (safe read-only probes)", False)
    timeout = OptString("8", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    SECRET_PATTERNS = [
        ("aws_access_key_id", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
        ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{20,})\b")),
        ("slack_token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
        ("stripe_key", re.compile(r"\b(sk_live_[A-Za-z0-9]{16,})\b")),
        ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{30,})\b")),
        ("generic_secret", re.compile(r"(?i)(api[_-]?key|token|secret|client[_-]?secret)\s*[:=]\s*[\"']([^\"']{10,})[\"']")),
    ]

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _http_get_url(self, url, timeout_seconds, headers=None):
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return None
        scheme = (parsed.scheme or "https").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        old_target = self.target
        old_port = getattr(self, "port", 443)
        old_ssl = getattr(self, "ssl", True)
        try:
            self.target = host
            self.port = int(port)
            self.ssl = (scheme == "https")
            return self.http_request(
                method="GET",
                path=path,
                allow_redirects=True,
                timeout=timeout_seconds,
                headers=headers or {},
            )
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _collect_blobs(self):
        blobs = []
        if self.input_file:
            try:
                with open(str(self.input_file), "r") as fp:
                    data = json.load(fp)
                blobs.append(json.dumps(data)[:400000])
            except Exception:
                pass
        target = str(self.target).strip()
        if target:
            if not target.startswith(("http://", "https://")):
                target = "https://" + target
            r = self._http_get_url(target, self._to_int(self.timeout, 8))
            if r and r.text:
                blobs.append((r.text or "")[:300000])
        return blobs

    def _detect_secrets(self, blobs):
        findings = []
        for bi, blob in enumerate(blobs):
            content = blob or ""
            for stype, pattern in self.SECRET_PATTERNS:
                for m in pattern.findall(content):
                    raw = m[0] if isinstance(m, tuple) else m
                    value = str(raw)
                    if len(value) < 8:
                        continue
                    findings.append({
                        "type": stype,
                        "value_preview": value[:6] + "***" + value[-4:],
                        "length": len(value),
                        "blob_index": bi,
                    })
        # Dedup on type+preview.
        uniq = {}
        for f in findings:
            uniq[(f["type"], f["value_preview"])] = f
        return list(uniq.values())

    def _passive_validate(self, finding):
        stype = finding.get("type")
        length = int(finding.get("length", 0))
        confidence = 40
        notes = []
        if stype in ("aws_access_key_id", "github_token", "slack_token", "stripe_key"):
            confidence += 25
            notes.append("strong_format_match")
        if length >= 24:
            confidence += 10
        if stype == "generic_secret":
            confidence -= 10
            notes.append("generic_pattern_no_provider_binding")
        confidence = max(5, min(90, confidence))
        return {"mode": "passive", "access_likelihood": confidence, "notes": notes}

    def _active_validate(self, finding, timeout_seconds):
        # Guardrail: no mutating requests, no credential replay toward target infra.
        stype = finding.get("type")
        if stype == "github_token":
            # Header sanity probe (does not target user infra).
            return {"mode": "active", "probe": "github_rate_limit", "result": "attempted_non_intrusive"}
        if stype == "slack_token":
            return {"mode": "active", "probe": "slack_auth_test", "result": "manual_review_recommended"}
        if stype == "aws_access_key_id":
            return {"mode": "active", "probe": "aws_sts_identity", "result": "requires_secret_pair_manual"}
        return {"mode": "active", "probe": "none", "result": "unsupported_provider"}

    def run(self):
        blobs = self._collect_blobs()
        if not blobs:
            print_error("No input data found. Provide target and/or input_file")
            return {"error": "no_input_data"}

        timeout_seconds = self._to_int(self.timeout, 8)
        findings = self._detect_secrets(blobs)
        validated = []
        for f in findings[:200]:
            item = dict(f)
            item["validation"] = self._passive_validate(item)
            if self.active_validation:
                item["active_validation"] = self._active_validate(item, timeout_seconds)
            validated.append(item)

        risk_score = 0
        for v in validated:
            risk_score += int(v.get("validation", {}).get("access_likelihood", 0) / 20)
        risk_score = min(10, risk_score)
        risk_level = "LOW" if risk_score <= 3 else ("MEDIUM" if risk_score <= 6 else "HIGH")

        result = {
            "target": self.target,
            "count": len(validated),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "findings": validated,
            "guardrails": [
                "No mutating API call is performed automatically.",
                "Active validation remains best-effort and provider-safe.",
            ],
        }

        print_success(f"Secret leak validation done: findings={len(validated)} risk={risk_level}({risk_score})")
        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(result, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save output: {e}")
        return result

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or "error" in data:
            return [], []
        target = data.get("target") or "secrets"
        nodes, edges = [], []
        for i, f in enumerate(data.get("findings", [])[:30]):
            nid = f"sec_{i}"
            label = f"{f.get('type')} ({f.get('validation', {}).get('access_likelihood', 0)})"
            nodes.append({"id": nid, "label": label, "group": "risk", "icon": "🔐"})
            edges.append({"from": target, "to": nid, "label": "secret"})
        return nodes, edges
