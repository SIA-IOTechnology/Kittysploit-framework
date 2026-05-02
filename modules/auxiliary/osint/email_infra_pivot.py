from kittysploit import *
import json
import dns.resolver


class Module(Auxiliary):
    __info__ = {
        "name": "Email Infra Pivot",
        "author": ["KittySploit Team"],
        "description": "Pivot on email infrastructure (MX/SPF/DMARC/DKIM) for a target domain.",
        "tags": ["osint", "passive", "email", "dns"],
    }

    target = OptString("", "Target domain (e.g. example.com)", required=True)
    timeout = OptString("8", "DNS timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _resolve(self, domain, rtype, timeout_seconds):
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout_seconds
        resolver.lifetime = timeout_seconds
        try:
            return [r.to_text().strip() for r in resolver.resolve(domain, rtype)]
        except Exception:
            return []

    def _extract_spf(self, txt_records):
        return [txt for txt in txt_records if "v=spf1" in txt.lower()]

    def _extract_dmarc(self, txt_records):
        return [txt for txt in txt_records if "v=dmarc1" in txt.lower()]

    def _score(self, mx, spf, dmarc, dkim_any):
        score = 0
        signals = []

        if not mx:
            score += 2
            signals.append("no_mx_records")
        if not spf:
            score += 2
            signals.append("spf_missing")
        if not dmarc:
            score += 3
            signals.append("dmarc_missing")
        if not dkim_any:
            score += 2
            signals.append("dkim_not_detected")

        # Weak DMARC policy hints
        for d in dmarc:
            low = d.lower()
            if "p=none" in low:
                score += 2
                signals.append("dmarc_policy_none")
            elif "p=quarantine" in low:
                score += 1
                signals.append("dmarc_policy_quarantine")

        level = "LOW"
        if score >= 7:
            level = "HIGH"
        elif score >= 4:
            level = "MEDIUM"

        return score, level, sorted(set(signals))

    def run(self):
        domain = str(self.target).strip().lower()
        if not domain:
            print_error("target is required")
            return {"error": "target is required"}

        timeout_seconds = self._to_int(self.timeout, 8)
        print_info(f"Analyzing email infrastructure for {domain}")

        mx = self._resolve(domain, "MX", timeout_seconds)
        txt = self._resolve(domain, "TXT", timeout_seconds)
        spf = self._extract_spf(txt)

        dmarc_domain = f"_dmarc.{domain}"
        dmarc_txt = self._resolve(dmarc_domain, "TXT", timeout_seconds)
        dmarc = self._extract_dmarc(dmarc_txt)

        # Common DKIM selectors (best effort).
        selectors = ["default", "selector1", "selector2", "google", "k1", "mail"]
        dkim_hits = []
        for sel in selectors:
            host = f"{sel}._domainkey.{domain}"
            recs = self._resolve(host, "TXT", timeout_seconds)
            if any("v=dkim1" in r.lower() for r in recs):
                dkim_hits.append({"selector": sel, "records": recs})

        score, level, signals = self._score(mx, spf, dmarc, bool(dkim_hits))

        data = {
            "target": domain,
            "mx": mx,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim_hits,
            "risk_score": score,
            "risk_level": level,
            "signals": signals,
        }

        print_success(
            f"Email infra summary: MX={len(mx)} SPF={len(spf)} DMARC={len(dmarc)} DKIM={len(dkim_hits)}"
        )
        print_info(f"Risk: {level} ({score})")
        if signals:
            print_info(f"Signals: {', '.join(signals)}")

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

        for mx in data.get("mx", [])[:15]:
            nid = f"mx_{mx}"
            nodes.append({"id": nid, "label": mx, "group": "mailserver", "icon": "📨"})
            edges.append({"from": target, "to": nid, "label": "MX"})

        rid = f"risk_{target}"
        nodes.append({
            "id": rid,
            "label": f"{data.get('risk_level', 'LOW')} ({data.get('risk_score', 0)})",
            "group": "generic",
            "icon": "⚠️",
        })
        edges.append({"from": target, "to": rid, "label": "email"})
        return nodes, edges
