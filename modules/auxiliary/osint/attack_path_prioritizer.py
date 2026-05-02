from kittysploit import *
import json
import re


class Module(Auxiliary):
    __info__ = {
        "name": "Attack Path Prioritizer",
        "author": ["KittySploit Team"],
        "description": "Correlate OSINT, identity and cloud findings into prioritized probable attack paths.",
        "tags": ["osint", "correlation", "attack-path", "prioritization"],
    }

    target = OptString("", "Target organization/domain/identity", required=True)
    identity_file = OptString("", "JSON output from identity_handle_hunter", required=False)
    js_file = OptString("", "JSON output from js_endpoint_extractor", required=False)
    breach_file = OptString("", "JSON output from breach_exposure_score", required=False)
    bucket_file = OptString("", "JSON output from public_bucket_hunter", required=False)
    aws_privesc_file = OptString("", "JSON output from post/aws/gather/iam_privesc_paths", required=False)
    domain_surface_file = OptString("", "JSON output from domain_surface_mapper", required=False)
    top_k = OptString("10", "Maximum prioritized paths to keep", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _load_json(self, path):
        if not path:
            return {}
        try:
            with open(str(path), "r") as fp:
                data = json.load(fp)
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _collect_signals(self, data):
        signals = {
            "identity_presence": 0,
            "key_hints": 0,
            "exposed_endpoints": 0,
            "external_domains": 0,
            "breach_score": 0,
            "public_buckets": 0,
            "aws_privesc_paths": 0,
            "weak_http": 0,
        }

        ident = data.get("identity", {})
        signals["identity_presence"] = len(ident.get("findings", []) or [])

        js = data.get("js", {})
        findings = js.get("findings", {}) or {}
        signals["key_hints"] = len(findings.get("key_hints", []) or [])
        signals["exposed_endpoints"] = len(findings.get("endpoints", []) or [])
        signals["external_domains"] = len(findings.get("external_domains", []) or [])

        breach = data.get("breach", {})
        signals["breach_score"] = int(breach.get("risk_score", 0) or 0)

        buckets = data.get("bucket", {})
        bucket_findings = buckets.get("findings", []) or []
        signals["public_buckets"] = len([x for x in bucket_findings if x.get("public")])

        aws = data.get("aws", {})
        path_list = aws.get("paths") or aws.get("findings") or []
        if isinstance(path_list, list):
            signals["aws_privesc_paths"] = len(path_list)

        surface = data.get("surface", {})
        weak_http = [
            x for x in (surface.get("http_checks", []) or [])
            if x.get("score", 100) < 60
        ]
        signals["weak_http"] = len(weak_http)
        return signals

    def _candidate_paths(self, target, signals):
        paths = []

        if signals["key_hints"] > 0 and signals["aws_privesc_paths"] > 0:
            paths.append({
                "name": "Client-side secret hint -> AWS principal pivot -> IAM privilege escalation",
                "chain": [target, "js_secret_hint", "aws_principal", "iam_privesc_path"],
                "impact": 5,
                "effort": 3,
                "confidence": min(95, 55 + (signals["key_hints"] * 5) + (signals["aws_privesc_paths"] * 4)),
                "reason": "JS key hints and IAM escalation paths coexist.",
            })

        if signals["identity_presence"] > 0 and signals["breach_score"] >= 3:
            paths.append({
                "name": "Identity footprint -> credential stuffing/phishing -> account compromise",
                "chain": [target, "identity_handles", "breach_signals", "account_takeover"],
                "impact": 4,
                "effort": 2,
                "confidence": min(90, 45 + (signals["identity_presence"] * 2) + (signals["breach_score"] * 5)),
                "reason": "High identity visibility combined with breach signals.",
            })

        if signals["public_buckets"] > 0 and signals["external_domains"] > 0:
            paths.append({
                "name": "External web exposure -> public bucket discovery -> data leakage pivot",
                "chain": [target, "external_domains", "public_bucket", "sensitive_data_exposure"],
                "impact": 4,
                "effort": 1,
                "confidence": min(92, 50 + (signals["public_buckets"] * 8)),
                "reason": "Public bucket findings indicate probable accessible data.",
            })

        if signals["exposed_endpoints"] >= 8 and signals["weak_http"] > 0:
            paths.append({
                "name": "Exposed API endpoints -> weak HTTP controls -> application compromise",
                "chain": [target, "client_api_endpoints", "weak_http_posture", "app_compromise"],
                "impact": 3,
                "effort": 2,
                "confidence": min(88, 40 + signals["exposed_endpoints"] + (signals["weak_http"] * 6)),
                "reason": "Large endpoint surface with weak transport/header hygiene.",
            })

        if not paths:
            paths.append({
                "name": "Recon baseline path",
                "chain": [target, "recon", "manual_validation"],
                "impact": 2,
                "effort": 3,
                "confidence": 35,
                "reason": "Insufficient correlated signals for strong automated chaining.",
            })
        return paths

    def _score_path(self, p):
        impact = int(p.get("impact", 1))
        effort = int(p.get("effort", 3))
        confidence = int(p.get("confidence", 0))
        # Higher impact/confidence and lower effort should rank first.
        return (impact * 20) + confidence - (effort * 12)

    def run(self):
        target = str(self.target).strip()
        if not target:
            print_error("target is required")
            return {"error": "target is required"}

        top_k = self._to_int(self.top_k, 10)
        data = {
            "identity": self._load_json(self.identity_file),
            "js": self._load_json(self.js_file),
            "breach": self._load_json(self.breach_file),
            "bucket": self._load_json(self.bucket_file),
            "aws": self._load_json(self.aws_privesc_file),
            "surface": self._load_json(self.domain_surface_file),
        }
        signals = self._collect_signals(data)
        paths = self._candidate_paths(target, signals)

        for p in paths:
            p["priority_score"] = self._score_path(p)

        paths = sorted(paths, key=lambda x: x.get("priority_score", 0), reverse=True)[:top_k]
        risk_score = min(10, max(1, int(sum(max(0, p["priority_score"]) for p in paths) / 80)))
        risk_level = "LOW" if risk_score <= 3 else ("MEDIUM" if risk_score <= 6 else "HIGH")

        result = {
            "target": target,
            "signals": signals,
            "count": len(paths),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "paths": paths,
        }

        print_success(f"Prioritized attack paths: {len(paths)} (risk={risk_level}/{risk_score})")
        for idx, p in enumerate(paths[:10], 1):
            print_info(
                f"  {idx}. {p['name']} | score={p['priority_score']} "
                f"| impact={p['impact']} effort={p['effort']} conf={p['confidence']}"
            )

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
        target = data.get("target", self.target)
        nodes, edges = [], []
        signals = data.get("signals", {}) or {}

        summary_id = f"path_summary_{target}"
        summary_info = (
            f"Global risk: {data.get('risk_level', 'UNKNOWN')} ({data.get('risk_score', 0)})\n"
            f"Paths: {data.get('count', 0)}\n"
            f"Signals: {json.dumps(signals, ensure_ascii=True)}"
        )
        nodes.append({
            "id": summary_id,
            "label": f"Attack paths summary ({data.get('risk_score', 0)})",
            "group": "risk",
            "icon": "📌",
            "custom_info": summary_info,
        })
        edges.append({
            "from": target,
            "to": summary_id,
            "label": "summary",
            "custom_info": "Aggregated prioritization output",
        })

        for i, p in enumerate(data.get("paths", [])[:12]):
            nid = f"path_{i}_{target}"
            label = f"{p.get('name', 'path')} ({p.get('priority_score', 0)})"
            path_info = (
                f"Reason: {p.get('reason', 'n/a')}\n"
                f"Impact: {p.get('impact', 'n/a')}/5\n"
                f"Effort: {p.get('effort', 'n/a')}/5\n"
                f"Confidence: {p.get('confidence', 0)}\n"
                f"Priority score: {p.get('priority_score', 0)}\n"
                f"Chain: {' -> '.join([str(x) for x in p.get('chain', [])])}"
            )
            nodes.append({
                "id": nid,
                "label": label[:90],
                "group": "risk",
                "icon": "🧭",
                "custom_info": path_info,
            })
            edges.append({
                "from": summary_id,
                "to": nid,
                "label": "attack_path",
                "custom_info": p.get("reason", ""),
            })
            for j, step in enumerate(p.get("chain", [])[:6]):
                sid = f"path_{i}_step_{j}_{target}"
                readable_step = re.sub(r"_", " ", str(step))
                nodes.append({
                    "id": sid,
                    "label": readable_step,
                    "group": "generic",
                    "icon": "➡️",
                    "custom_info": f"Path {i + 1} - step {j + 1}: {readable_step}",
                })
                edges.append({
                    "from": nid if j == 0 else f"path_{i}_step_{j-1}_{target}",
                    "to": sid,
                    "label": "step",
                    "custom_info": f"Step {j + 1} in path '{p.get('name', 'path')}'",
                })
        return nodes, edges
