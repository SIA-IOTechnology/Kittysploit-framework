from kittysploit import *
import json
import re
import dns.resolver


class Module(Auxiliary):
    __info__ = {
        "name": "Mail Security Posture",
        "author": ["KittySploit Team"],
        "description": (
            "Assess outbound email security posture (MX stack, SPF, DMARC, DKIM) and classify "
            "likely SaaS mail providers (Microsoft 365, Google Workspace, SEGs) for an organization domain."
        ),
        "tags": ["osint", "passive", "email", "dns", "posture"],
    }

    target = OptString("", "Target domain (e.g. example.com)", required=True)
    timeout = OptString("8", "DNS timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    _MX_PROVIDER = (
        (re.compile(r"outlook\.com|protection\.outlook\.com|olc\.protection\.outlook\.com", re.I), "microsoft_365"),
        (re.compile(r"google\.com|l\.google\.com", re.I), "google_workspace"),
        (re.compile(r"pphosted\.com", re.I), "proofpoint"),
        (re.compile(r"mimecast\.com|mimecast\.co", re.I), "mimecast"),
        (re.compile(r"mailgun\.org", re.I), "mailgun"),
        (re.compile(r"sendgrid\.net", re.I), "sendgrid"),
        (re.compile(r"zendesk\.com", re.I), "zendesk"),
        (re.compile(r"intercom\.io|intercom-mail\.com", re.I), "intercom"),
        (re.compile(r"amazonaws\.com|ses\.|email\.us-east", re.I), "amazon_ses"),
        (re.compile(r"sparkpostmail\.com", re.I), "sparkpost"),
    )

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

    def _mx_hosts(self, mx_records):
        hosts = []
        for line in mx_records:
            parts = line.split()
            if len(parts) >= 2:
                hosts.append(parts[-1].rstrip(".").lower())
        return hosts

    def _classify_mx_providers(self, mx_records):
        hosts = self._mx_hosts(mx_records)
        tags = []
        for host in hosts:
            for rx, name in self._MX_PROVIDER:
                if rx.search(host):
                    tags.append({"host": host, "provider": name})
                    break
        return tags

    def _extract_spf(self, txt_records):
        return [txt for txt in txt_records if "v=spf1" in txt.lower()]

    def _extract_dmarc(self, txt_records):
        return [txt for txt in txt_records if "v=dmarc1" in txt.lower()]

    def _dmarc_policy(self, dmarc_records):
        policies = []
        for d in dmarc_records:
            low = d.lower()
            p = "unknown"
            if "p=reject" in low:
                p = "reject"
            elif "p=quarantine" in low:
                p = "quarantine"
            elif "p=none" in low:
                p = "none"
            sp = "unknown"
            if "sp=reject" in low:
                sp = "reject"
            elif "sp=quarantine" in low:
                sp = "quarantine"
            elif "sp=none" in low:
                sp = "none"
            pct_m = re.search(r"pct=(\d+)", low)
            policies.append({"record": d, "p": p, "sp": sp, "pct": pct_m.group(1) if pct_m else None})
        return policies

    def _score(self, mx, spf, dmarc_policies, dkim_any, mx_providers):
        score = 0
        signals = []

        if not mx:
            score += 3
            signals.append("no_mx")
        if not spf:
            score += 2
            signals.append("spf_missing")
        if not dmarc_policies:
            score += 4
            signals.append("dmarc_missing")

        for pol in dmarc_policies:
            if pol.get("p") == "none":
                score += 3
                signals.append("dmarc_p_none")
            elif pol.get("p") == "quarantine":
                score += 1
                signals.append("dmarc_p_quarantine")

        if not dkim_any:
            score += 1
            signals.append("dkim_not_detected_common_selectors")

        # Third-party mail SaaS without DMARC is common risk context
        if mx_providers and not dmarc_policies:
            score += 1
            signals.append("saas_mx_without_dmarc")

        level = "LOW"
        if score >= 8:
            level = "HIGH"
        elif score >= 4:
            level = "MEDIUM"

        return score, level, sorted(set(signals))

    def run(self):
        domain = str(self.target).strip().lower()
        if not domain or "." not in domain:
            print_error("target must be a valid domain")
            return {"error": "invalid_domain"}

        timeout_seconds = self._to_int(self.timeout, 8)
        print_info(f"Mail security posture for {domain}")

        mx = self._resolve(domain, "MX", timeout_seconds)
        txt = self._resolve(domain, "TXT", timeout_seconds)
        spf = self._extract_spf(txt)

        dmarc_domain = f"_dmarc.{domain}"
        dmarc_txt = self._resolve(dmarc_domain, "TXT", timeout_seconds)
        dmarc = self._extract_dmarc(dmarc_txt)
        dmarc_policies = self._dmarc_policy(dmarc)

        selectors = ["default", "selector1", "selector2", "google", "k1", "mail", "s1", "s2"]
        dkim_hits = []
        for sel in selectors:
            host = f"{sel}._domainkey.{domain}"
            recs = self._resolve(host, "TXT", timeout_seconds)
            if any("v=dkim1" in r.lower() for r in recs):
                dkim_hits.append({"selector": sel, "records": recs})

        mx_providers = self._classify_mx_providers(mx)
        score, level, signals = self._score(mx, spf, dmarc_policies, bool(dkim_hits), mx_providers)

        data = {
            "target": domain,
            "mx": mx,
            "mx_provider_guess": mx_providers,
            "spf": spf,
            "dmarc": dmarc,
            "dmarc_policies": dmarc_policies,
            "dkim": dkim_hits,
            "posture_score": score,
            "posture_level": level,
            "signals": signals,
        }

        print_success(f"MX={len(mx)} SPF={len(spf)} DMARC={len(dmarc)} DKIM={len(dkim_hits)}")
        print_info(f"Posture: {level} ({score}) — {', '.join(signals) if signals else 'no negative signals'}")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as f:
                    json.dump(data, f, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as e:
                print_error(f"Failed to save output: {e}")

        return data

    def get_graph_nodes(self, data):
        if not isinstance(data, dict) or data.get("error"):
            return [], []

        target = data.get("target", self.target)
        nodes = []
        edges = []

        for p in data.get("mx_provider_guess", [])[:12]:
            nid = f"mxp_{p.get('host')}"
            nodes.append({"id": nid, "label": f"{p.get('provider')}", "group": "mail_saas", "icon": "📬"})
            edges.append({"from": target, "to": nid, "label": p.get("host", "mx")})

        rid = f"posture_{target}"
        nodes.append(
            {
                "id": rid,
                "label": f"{data.get('posture_level','?')} ({data.get('posture_score',0)})",
                "group": "risk",
                "icon": "🛡️",
            }
        )
        edges.append({"from": target, "to": rid, "label": "posture"})
        return nodes, edges
