from kittysploit import *
import json
import dns.resolver
from lib.protocols.http.http_client import Http_client
from urllib.parse import urlparse


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Typosquat Detector",
        "author": ["KittySploit Team"],
        "description": "Generate likely typosquatted domains and test DNS/HTTP activity.",
        "tags": ["osint", "passive", "domain", "brand"],
    }

    target = OptString("", "Target domain (e.g. example.com)", required=True)
    max_candidates = OptString("80", "Maximum typo candidates", required=False)
    timeout = OptString("6", "DNS/HTTP timeout in seconds", required=False)
    strict_mode = OptBool(True, "Reduce noise by filtering parking/low-confidence hits", False)
    min_confidence = OptString("70", "Minimum confidence to keep a finding (0-100)", required=False)
    include_parking = OptBool(False, "Include parking-like domains in final findings", False)
    output_file = OptString("", "Optional JSON output file", required=False)

    COMMON_TLDS = ["com", "net", "org", "io", "co", "app", "dev", "tech"]
    PARKING_MARKERS = [
        "domain for sale",
        "buy this domain",
        "this domain is for sale",
        "sedo",
        "afternic",
        "dan.com",
        "parkingcrew",
        "bodis",
        "undeveloped",
        "namecheap parking",
        "godaddy",
    ]

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _normalize_domain(self, value):
        v = str(value).strip().lower()
        v = v.replace("https://", "").replace("http://", "").split("/", 1)[0].strip(".")
        if "@" in v or "." not in v:
            return None
        return v

    def _split_domain(self, domain):
        parts = domain.split(".")
        if len(parts) < 2:
            return domain, ""
        return ".".join(parts[:-1]), parts[-1]

    def _generate_candidates(self, domain):
        sld, tld = self._split_domain(domain)
        out = set()

        # Character omission
        for i in range(len(sld)):
            if len(sld) > 2:
                out.add(sld[:i] + sld[i + 1:] + "." + tld)

        # Adjacent swap
        for i in range(len(sld) - 1):
            swapped = list(sld)
            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            out.add("".join(swapped) + "." + tld)

        # Character substitution (limited)
        for i in range(min(len(sld), 6)):
            for c in "aeioul1o0":
                if sld[i] != c:
                    out.add(sld[:i] + c + sld[i + 1:] + "." + tld)

        # Prefix/suffix additions
        out.add("my" + sld + "." + tld)
        out.add(sld + "online." + tld)
        out.add(sld + "-secure." + tld)
        out.add(sld + "-login." + tld)

        # TLD variants
        for alt in self.COMMON_TLDS:
            if alt != tld:
                out.add(sld + "." + alt)

        out.discard(domain)
        return sorted(d for d in out if len(d.split(".")[0]) >= 2)

    def _resolves(self, domain, timeout_seconds):
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout_seconds
        resolver.lifetime = timeout_seconds
        try:
            a = resolver.resolve(domain, "A")
            return True, [r.to_text() for r in a][:3]
        except Exception:
            return False, []

    def _looks_like_parking(self, body, title):
        blob = f"{title} {body}".lower()
        return any(marker in blob for marker in self.PARKING_MARKERS)

    def _http_status(self, domain, timeout_seconds):
        for url in (f"https://{domain}", f"http://{domain}"):
            parsed = urlparse(url)
            host = parsed.hostname
            if not host:
                continue
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
                r = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=True,
                    timeout=timeout_seconds,
                )
                text = (r.text or "")[:4500]
                title = ""
                try:
                    import re as _re
                    m = _re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
                    if m:
                        title = " ".join(m.group(1).split())[:140]
                except Exception:
                    pass
                parking = self._looks_like_parking(text, title)
                return r.status_code, r.url, parking, title
            except Exception:
                continue
            finally:
                self.target = old_target
                self.port = old_port
                self.ssl = old_ssl
        return None, None, False, ""

    def run(self):
        domain = self._normalize_domain(self.target)
        if not domain:
            print_error("target must be a valid domain")
            return {"error": "invalid domain target"}

        timeout_seconds = self._to_int(self.timeout, 6)
        max_candidates = self._to_int(self.max_candidates, 80)
        min_confidence = min(100, self._to_int(self.min_confidence, 70))
        candidates = self._generate_candidates(domain)[:max_candidates]
        print_info(f"Testing {len(candidates)} typo candidates for {domain}")

        target_sld, target_tld = self._split_domain(domain)
        findings = []
        for c in candidates:
            resolved, ips = self._resolves(c, timeout_seconds)
            if not resolved:
                continue
            status, final_url, parking, title = self._http_status(c, timeout_seconds)
            cand_sld, cand_tld = self._split_domain(c)
            confidence = 40
            if status in (200, 301, 302):
                confidence += 20
            if target_sld in cand_sld:
                confidence += 10
            # same TLD typo is usually higher relevance than changed TLD
            if cand_tld == target_tld:
                confidence += 10
            elif cand_tld in self.COMMON_TLDS:
                confidence += 4

            if parking:
                confidence -= 18
            # Very short typo labels often noisy unless active and non-parking.
            if len(cand_sld) <= 3:
                confidence -= 8

            confidence = max(0, min(95, confidence))
            if self.strict_mode and confidence < min_confidence:
                continue
            if parking and not self.include_parking:
                continue

            findings.append({
                "domain": c,
                "resolved": resolved,
                "ips": ips,
                "http_status": status,
                "url": final_url,
                "parking_like": parking,
                "title": title,
                "confidence": confidence,
            })

        findings = sorted(findings, key=lambda x: x.get("confidence", 0), reverse=True)
        risk_level = "LOW"
        high_conf = len([f for f in findings if f.get("confidence", 0) >= 82])
        if high_conf >= 4 or len(findings) >= 8:
            risk_level = "HIGH"
        elif high_conf >= 1 or len(findings) >= 3:
            risk_level = "MEDIUM"

        data = {
            "target": domain,
            "tested": len(candidates),
            "count": len(findings),
            "risk_level": risk_level,
            "findings": findings,
        }

        print_success(f"Typosquat candidates active: {len(findings)} (risk={risk_level})")
        for f in findings[:15]:
            print_info(
                f"  {f['domain']} | status={f.get('http_status')} | "
                f"parking_like={f.get('parking_like')} | confidence={f['confidence']}"
            )

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save output: {e}")
        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or "error" in data:
            return [], []
        target = data.get("target", self.target)
        nodes, edges = [], []
        for i, f in enumerate(data.get("findings", [])[:20]):
            nid = f"typo_{i}_{target}"
            nodes.append({"id": nid, "label": f"{f.get('domain')} ({f.get('confidence')})", "group": "domain", "icon": "🧬"})
            edges.append({"from": target, "to": nid, "label": "typosquat"})
        return nodes, edges
