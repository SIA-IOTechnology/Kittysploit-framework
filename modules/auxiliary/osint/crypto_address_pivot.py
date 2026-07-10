from kittysploit import *
import json
import re

from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Crypto Address Pivot",
        "author": ["KittySploit Team"],
        "description": (
            "Extract cryptocurrency addresses from OSINT text/artifacts and enrich "
            "via public blockchain APIs (Blockchair). Passive — no wallet interaction."
        ),
        "tags": ["osint", "passive", "crypto", "le"],
    }

    target = OptString("", "Search term, domain, or raw text seed", required=True)
    source_file = OptString("", "Optional JSON file from prior OSINT modules", required=False)
    enrich = OptBool(True, "Query public Blockchair API for address metadata", required=False)
    max_addresses = OptString("12", "Maximum addresses to enrich", required=False)
    timeout = OptString("12", "HTTP timeout in seconds", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    BTC_RE = re.compile(r"\b((?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62})\b")
    ETH_RE = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")

    def _to_int(self, value, default_value):
        try:
            return max(1, int(str(value).strip()))
        except Exception:
            return default_value

    def _http_get_host(self, host, path, timeout_seconds, headers=None):
        old_target = self.target
        try:
            self.target = host
            self.port = 443
            self.ssl = True
            return self.http_request(
                method="GET",
                path=path,
                allow_redirects=True,
                timeout=timeout_seconds,
                headers=headers or {"User-Agent": "KittyOSINT/1.0"},
            )
        except Exception:
            return None
        finally:
            self.target = old_target

    def _load_source_blob(self, path):
        if not path:
            return ""
        try:
            with open(str(path), "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return json.dumps(data)
        except Exception:
            try:
                with open(str(path), "r", encoding="utf-8") as handle:
                    return handle.read()
            except Exception:
                return ""

    def _extract_addresses(self, blob):
        btc = list(dict.fromkeys(self.BTC_RE.findall(blob or "")))
        eth = list(dict.fromkeys(self.ETH_RE.findall(blob or "")))
        return btc, eth

    def _blockchair_btc(self, address, timeout_seconds):
        path = f"/bitcoin/dashboards/address/{address}?limit=1"
        resp = self._http_get_host("api.blockchair.com", path, timeout_seconds)
        if not resp or resp.status_code != 200:
            return {}
        try:
            data = resp.json()
            row = (data.get("data") or {}).get(address) or {}
            addr = row.get("address") or {}
            return {
                "balance_sat": addr.get("balance"),
                "tx_count": addr.get("transaction_count"),
                "received_sat": addr.get("received"),
            }
        except Exception:
            return {}

    def _blockchair_eth(self, address, timeout_seconds):
        path = f"/ethereum/dashboards/address/{address}?limit=1"
        resp = self._http_get_host("api.blockchair.com", path, timeout_seconds)
        if not resp or resp.status_code != 200:
            return {}
        try:
            data = resp.json()
            row = (data.get("data") or {}).get(address) or {}
            addr = row.get("address") or {}
            return {
                "balance_wei": addr.get("balance"),
                "tx_count": addr.get("transaction_count"),
            }
        except Exception:
            return {}

    def run(self):
        seed = str(self.target or "").strip()
        if not seed:
            print_error("target is required")
            return {"error": "invalid target"}

        timeout_seconds = self._to_int(self.timeout, 12)
        max_addresses = self._to_int(self.max_addresses, 12)
        blob = seed + "\n" + self._load_source_blob(self.source_file)
        btc_list, eth_list = self._extract_addresses(blob)

        findings = []
        for addr in btc_list[:max_addresses]:
            meta = self._blockchair_btc(addr, timeout_seconds) if self.enrich else {}
            findings.append({
                "address": addr,
                "chain": "bitcoin",
                "source": "regex_extract",
                "enrichment": meta,
                "confidence": 85 if meta else 70,
                "source_url": f"https://blockchair.com/bitcoin/address/{addr}",
            })
        for addr in eth_list[:max_addresses]:
            meta = self._blockchair_eth(addr, timeout_seconds) if self.enrich else {}
            findings.append({
                "address": addr,
                "chain": "ethereum",
                "source": "regex_extract",
                "enrichment": meta,
                "confidence": 85 if meta else 70,
                "source_url": f"https://blockchair.com/ethereum/address/{addr}",
            })

        result = {
            "target": seed,
            "findings": findings,
            "addresses": [f["address"] for f in findings],
            "crypto_addresses": [f["address"] for f in findings],
            "address_count": len(findings),
            "source_urls": [f.get("source_url") for f in findings if f.get("source_url")],
        }

        if not findings:
            print_info("No cryptocurrency addresses found in seed or source file")
        else:
            print_success(f"Crypto addresses extracted/enriched: {len(findings)}")

        if self.output_file:
            try:
                with open(str(self.output_file), "w", encoding="utf-8") as handle:
                    json.dump(result, handle, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")

        return result
