from kittysploit import *
import json
import re


class Module(Auxiliary):
    __info__ = {
        "name": "Identity Exposure Graph",
        "author": ["KittySploit Team"],
        "description": "Link human and machine identity artifacts and score real exploitability.",
        "tags": ["osint", "identity", "graph", "correlation"],
    }

    query = OptString("", "Identity seed (email, username, or full name)", required=True)
    identity_file = OptString("", "JSON output from identity_handle_hunter", required=False)
    breach_file = OptString("", "JSON output from breach_exposure_score", required=False)
    js_file = OptString("", "JSON output from js_endpoint_extractor", required=False)
    domain_surface_file = OptString("", "JSON output from domain_surface_mapper", required=False)
    bucket_file = OptString("", "JSON output from public_bucket_hunter", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _load_json(self, path):
        if not path:
            return {}
        try:
            with open(str(path), "r") as fp:
                data = json.load(fp)
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _extract_seed_parts(self, query):
        q = str(query).strip().lower()
        parts = {"raw": q, "emails": [], "handles": [], "domains": []}
        if "@" in q:
            parts["emails"].append(q)
            local, dom = q.split("@", 1)
            if local:
                parts["handles"].append(local)
            if "." in dom:
                parts["domains"].append(dom)
        else:
            cleaned = re.sub(r"[^a-z0-9._\- ]", " ", q)
            atoms = [x for x in cleaned.split() if x]
            if atoms:
                parts["handles"].extend(atoms[:5])
            for a in atoms:
                if "." in a and len(a) > 3:
                    parts["domains"].append(a)
        return parts

    def _build_entities(self, seed, identity, breach, js, surface, bucket):
        entities = {
            "person": [],
            "handle": [],
            "email": [],
            "domain": [],
            "repo_or_profile": [],
            "bucket": [],
            "asn_or_ip": [],
            "signal": [],
        }
        links = []

        root = seed["raw"] or "identity"
        entities["person"].append(root)
        for h in seed["handles"]:
            entities["handle"].append(h)
            links.append((root, h, "handle"))
        for e in seed["emails"]:
            entities["email"].append(e)
            links.append((root, e, "email"))
        for d in seed["domains"]:
            entities["domain"].append(d)
            links.append((root, d, "domain"))

        for f in identity.get("findings", [])[:50]:
            profile = f.get("url")
            handle = f.get("handle")
            if handle:
                entities["handle"].append(handle)
                links.append((root, handle, "observed"))
            if profile:
                entities["repo_or_profile"].append(profile)
                links.append((handle or root, profile, f.get("platform", "profile")))

        for f in bucket.get("findings", [])[:30]:
            b = f"{f.get('provider')}:{f.get('bucket')}"
            entities["bucket"].append(b)
            dom = bucket.get("target") or (seed["domains"][0] if seed["domains"] else root)
            links.append((dom, b, "bucket"))

        for d in (surface.get("subdomains", [])[:40] or []):
            entities["domain"].append(d)
            links.append((surface.get("target", root), d, "subdomain"))
        for ip in (surface.get("dns", {}).get("A", [])[:20] or []):
            entities["asn_or_ip"].append(ip)
            links.append((surface.get("target", root), ip, "A"))

        for r in breach.get("reasons", [])[:10]:
            entities["signal"].append(r)
            links.append((root, r, "risk_signal"))

        jsf = js.get("findings", {}) or {}
        for dom in (jsf.get("external_domains", [])[:30] or []):
            entities["domain"].append(dom)
            links.append((js.get("target", root), dom, "external"))
        for k in (jsf.get("key_hints", [])[:15] or []):
            sig = f"key_hint:{k.get('name', 'secret')}"
            entities["signal"].append(sig)
            links.append((js.get("target", root), sig, "secret_hint"))

        # Deduplicate while preserving order.
        for k in list(entities.keys()):
            seen = set()
            uniq = []
            for v in entities[k]:
                s = str(v).strip()
                if not s or s in seen:
                    continue
                seen.add(s)
                uniq.append(s)
            entities[k] = uniq
        return entities, links

    def _score_exploitability(self, entities, breach):
        score = 0
        reasons = []
        c_handles = len(entities.get("handle", []))
        c_profiles = len(entities.get("repo_or_profile", []))
        c_domains = len(entities.get("domain", []))
        c_buckets = len(entities.get("bucket", []))
        c_signals = len(entities.get("signal", []))

        if c_handles >= 5:
            score += 2
            reasons.append("large_handle_footprint")
        elif c_handles >= 2:
            score += 1
            reasons.append("multiple_handles")

        if c_profiles >= 3:
            score += 2
            reasons.append("multiple_public_profiles")

        if c_domains >= 8:
            score += 2
            reasons.append("wide_domain_graph")

        if c_buckets > 0:
            score += 2
            reasons.append("cloud_storage_exposure")

        if c_signals > 0:
            score += 2
            reasons.append("secret_or_breach_signals")

        score += min(2, int(breach.get("risk_score", 0) / 4))
        level = "LOW" if score <= 3 else ("MEDIUM" if score <= 6 else "HIGH")
        return score, level, reasons

    def run(self):
        query = str(self.query).strip()
        if not query:
            print_error("query is required")
            return {"error": "query is required"}

        identity = self._load_json(self.identity_file)
        breach = self._load_json(self.breach_file)
        js = self._load_json(self.js_file)
        surface = self._load_json(self.domain_surface_file)
        bucket = self._load_json(self.bucket_file)

        seed = self._extract_seed_parts(query)
        entities, links = self._build_entities(seed, identity, breach, js, surface, bucket)
        score, level, reasons = self._score_exploitability(entities, breach)

        result = {
            "query": query,
            "entities": entities,
            "links": [{"from": a, "to": b, "type": t} for (a, b, t) in links[:400]],
            "entity_counts": {k: len(v) for k, v in entities.items()},
            "exploitability_score": score,
            "exploitability_level": level,
            "reasons": reasons,
        }

        print_success(
            f"Identity graph ready: entities={sum(result['entity_counts'].values())} "
            f"links={len(result['links'])} exploitability={level}({score})"
        )
        if reasons:
            print_info(f"Signals: {', '.join(reasons)}")

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

        nodes = []
        edges = []
        entities = data.get("entities", {})
        summary_id = "idexp_summary"
        nodes.append({
            "id": summary_id,
            "label": f"Identity exposure ({data.get('exploitability_level', 'LOW')}:{data.get('exploitability_score', 0)})",
            "group": "risk",
            "icon": "📌",
            "custom_info": (
                f"Exploitability: {data.get('exploitability_level', 'LOW')} ({data.get('exploitability_score', 0)})\n"
                f"Reasons: {', '.join(data.get('reasons', []) or ['none'])}\n"
                f"Entity counts: {json.dumps(data.get('entity_counts', {}), ensure_ascii=True)}"
            ),
        })
        group_icon = {
            "person": ("generic", "🧑"),
            "handle": ("hostname", "👤"),
            "email": ("hostname", "📧"),
            "domain": ("domain", "🌐"),
            "repo_or_profile": ("generic", "🧪"),
            "bucket": ("hostname", "🪣"),
            "asn_or_ip": ("ip", "🖥️"),
            "signal": ("risk", "🚨"),
        }
        node_ids = {}
        idx = 0
        for k, vals in entities.items():
            group, icon = group_icon.get(k, ("generic", "•"))
            for v in vals[:50]:
                nid = f"idexp_{idx}"
                idx += 1
                node_ids[v] = nid
                nodes.append({
                    "id": nid,
                    "label": str(v)[:80],
                    "group": group,
                    "icon": icon,
                    "custom_info": f"Entity type: {k}\nValue: {str(v)}",
                })
                if k in ("person", "handle", "email", "signal"):
                    edges.append({
                        "from": summary_id,
                        "to": nid,
                        "label": "entity",
                        "custom_info": f"Category: {k}",
                    })

        for l in data.get("links", [])[:300]:
            a = l.get("from")
            b = l.get("to")
            if a in node_ids and b in node_ids:
                relation = l.get("type", "link")
                edges.append({
                    "from": node_ids[a],
                    "to": node_ids[b],
                    "label": relation,
                    "custom_info": f"Relation: {relation}\nFrom: {a}\nTo: {b}",
                })
        return nodes, edges
