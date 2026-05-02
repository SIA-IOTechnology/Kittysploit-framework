from kittysploit import *
import json
import re
from urllib.parse import urlparse
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Breach Exposure Score",
        "author": ["KittySploit Team"],
        "description": "Estimate exposure risk for a domain/email using passive public breach signals.",
        "tags": ["osint", "passive", "breach", "risk"],
    }

    target = OptString("", "Target domain or email", required=True)
    target_type = OptString("domain", "Target type: domain|email", required=False)
    max_results = OptString("50", "Maximum findings to keep", required=False)
    timeout = OptString("10", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    # Public passive source used without authentication.
    # Endpoint: https://haveibeenpwned.com/Passwords (k-anon style) is password-specific
    # and not directly suitable here without handling sensitive inputs.
    # For safe passive identity exposure, use IntelX public API endpoint when available.
    # This module remains best-effort and can be extended with API-backed providers later.
    INTELX_SEARCH_URL = "https://2.intelx.io/intelligent/search"

    def _http_post_json_url(self, url, payload, timeout_seconds, headers=None):
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
                method="POST",
                path=path,
                timeout=timeout_seconds,
                headers=headers or {},
                data=json.dumps(payload),
            )
        except Exception:
            return None
        finally:
            self.target = old_target
            self.port = old_port
            self.ssl = old_ssl

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _normalize_target(self, target, target_type):
        t = str(target).strip().lower()
        tt = str(target_type).strip().lower()

        if tt not in ("domain", "email"):
            tt = "domain"

        if tt == "email":
            if "@" not in t:
                return None, None, "Invalid email target"
            return t, "email", None

        # domain
        t = re.sub(r"^https?://", "", t)
        t = t.split("/", 1)[0].strip(".")
        if not t or "." not in t:
            return None, None, "Invalid domain target"
        return t, "domain", None

    def _intelx_search(self, term, timeout_seconds):
        # Best-effort passive search. IntelX may throttle/deny unauthenticated calls.
        # We keep graceful error handling and return no results when unavailable.
        payload = {
            "term": term,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": 20,
            "timeout": max(2, timeout_seconds),
            "datefrom": "",
            "dateto": "",
            "sort": 2,
            "media": 0,
            "terminate": [],
        }
        headers = {
            "User-Agent": "KittyOSINT/1.0",
            "x-key": "",
            "Content-Type": "application/json",
        }
        try:
            resp = self._http_post_json_url(self.INTELX_SEARCH_URL, payload, timeout_seconds, headers=headers)
            if not resp:
                return []
            if resp.status_code not in (200, 401, 403):
                return []
            if resp.status_code in (401, 403):
                return []
            data = resp.json()
            records = []
            for item in data.get("records", []):
                records.append({
                    "source": "intelx",
                    "systemid": item.get("systemid"),
                    "name": item.get("name"),
                    "date": item.get("date"),
                    "mediah": item.get("mediah"),
                    "storageid": item.get("storageid"),
                })
            return records
        except Exception:
            return []

    def _extract_exposure_indicators(self, target, target_type):
        # Lightweight passive indicators from search engines are deliberately omitted
        # to avoid brittle scraping behavior. Keep deterministic via curated patterns.
        indicators = []
        if target_type == "email":
            local, domain = target.split("@", 1)
            if len(local) < 6:
                indicators.append({
                    "type": "weak_identifier",
                    "value": "short_email_local_part",
                    "weight": 1,
                    "reason": "Short mailbox names are easier to enumerate in credential stuffing datasets.",
                })
            if any(x in local for x in ["admin", "root", "it", "support", "ops", "security"]):
                indicators.append({
                    "type": "high_value_mailbox",
                    "value": local,
                    "weight": 2,
                    "reason": "Role-based mailbox likely targeted in phishing and data breaches.",
                })
            # Domain-level org mailbox heuristic.
            if re.match(r"^(gmail|yahoo|outlook|hotmail)\.", domain):
                indicators.append({
                    "type": "public_email_provider",
                    "value": domain,
                    "weight": 1,
                    "reason": "Public providers are common in exposed credential combos.",
                })
        else:
            # Domain heuristics.
            if target.count(".") >= 2:
                indicators.append({
                    "type": "multi_level_domain",
                    "value": target,
                    "weight": 1,
                    "reason": "Multi-level domains often reflect broad sub-brand attack surface.",
                })
            if any(k in target for k in ["corp", "internal", "admin", "vpn", "dev", "staging"]):
                indicators.append({
                    "type": "sensitive_naming_pattern",
                    "value": target,
                    "weight": 2,
                    "reason": "Naming hints at potentially sensitive organizational usage.",
                })
        return indicators

    def _score(self, indicators, breach_records):
        score = 0
        reasons = []

        for ind in indicators:
            w = int(ind.get("weight", 0))
            score += w
            reasons.append(ind.get("reason", ""))

        if breach_records:
            # Heavier weight for actual public breach-intel hits.
            score += min(6, len(breach_records))
            reasons.append(f"Public breach-index hits detected: {len(breach_records)}")

        if score >= 8:
            level = "CRITICAL"
        elif score >= 5:
            level = "HIGH"
        elif score >= 3:
            level = "MEDIUM"
        else:
            level = "LOW"

        return score, level, [r for r in reasons if r]

    def run(self):
        target_raw = str(self.target).strip()
        target_type_raw = str(self.target_type).strip()
        timeout_seconds = self._to_int(self.timeout, 10)
        max_results = self._to_int(self.max_results, 50)

        target, target_type, err = self._normalize_target(target_raw, target_type_raw)
        if err:
            print_error(err)
            return {"error": err}

        print_info(f"Assessing breach exposure for: {target} ({target_type})")

        indicators = self._extract_exposure_indicators(target, target_type)
        intelx_records = self._intelx_search(target, timeout_seconds)
        intelx_records = intelx_records[:max_results]

        score, level, reasons = self._score(indicators, intelx_records)

        findings = []
        findings.extend(indicators)
        for rec in intelx_records:
            findings.append({
                "type": "breach_index_hit",
                "value": rec.get("name") or rec.get("systemid"),
                "weight": 1,
                "source": rec.get("source"),
                "date": rec.get("date"),
            })

        data = {
            "target": target,
            "target_type": target_type,
            "risk_score": score,
            "risk_level": level,
            "reasons": reasons,
            "count": len(findings),
            "findings": findings[:max_results],
            "sources": {
                "intelx_records": len(intelx_records),
            },
        }

        print_info("=" * 80)
        print_success(f"Exposure score: {level} ({score})")
        for reason in reasons[:6]:
            print_info(f"  - {reason}")
        print_info(f"Findings: {data['count']}")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as f:
                    json.dump(data, f, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save output: {e}")

        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or "error" in data:
            return [], []

        target = data.get("target", self.target)
        nodes = []
        edges = []

        # Risk node
        rid = f"risk_{target}"
        nodes.append({
            "id": rid,
            "label": f"{data.get('risk_level', 'UNKNOWN')} ({data.get('risk_score', 0)})",
            "group": "risk",
            "icon": "🚨",
        })
        edges.append({"from": target, "to": rid, "label": "exposure"})

        # Findings nodes
        for i, f in enumerate(data.get("findings", [])[:20]):
            nid = f"finding_{i}_{target}"
            label = f"{f.get('type')}: {str(f.get('value', 'n/a'))[:55]}"
            nodes.append({
                "id": nid,
                "label": label,
                "group": "finding",
                "icon": "🧩",
            })
            edges.append({"from": rid, "to": nid, "label": "signal"})

        return nodes, edges
