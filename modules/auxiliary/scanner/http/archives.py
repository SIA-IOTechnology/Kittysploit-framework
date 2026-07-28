from kittysploit import *
from lib.protocols.http.http_client import Http_client
import requests
from urllib.parse import urlparse


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'Check archive website',
        'description': (
            'Query the Wayback Machine CDX API for historical URLs of the target host. '
            'By default only samples a small set of URLs (does not hammer the live site).'
        ),
        'author': 'KittySploit Team',
        'tags': ['web', 'scanner', 'osint', 'wayback'],
        'agent': {
            'risk': 'passive',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': False,
            'produces': ['endpoints'],
            'cost': 1.2,
            'noise': 0.3,
            'value': 0.6,
            'requires': {
                'min_endpoints': 0,
                'min_params': 0,
                'tech_hints_any': [],
                'tech_hints_all': [],
                'specializations_any': [],
                # Avoid launching during generic active fuzz waves unless OSINT is wanted.
                'risk_signals_any': [],
                'auth_session': False,
                'capabilities_any': [],
                'capabilities_all': [],
                'confidence_min': {},
                'confidence_min_any': {},
                'endpoint_pattern_any': [],
                'param_any': [],
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'endpoints', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {'website': 'hostname'},
                'suggested_followups': [],
            },
        },
    }

    website = OptString("", "Website host to archive-search (defaults to module target host)", True)
    max_urls = OptInteger(25, "Max Wayback URLs to list", required=False)
    probe_live = OptBool(
        False,
        "Also HTTP-probe listed archive URLs against the live internet (slow/noisy)",
        required=False,
    )
    probe_limit = OptInteger(10, "Max live probes when probe_live=true", required=False, advanced=True)

    def _resolve_host(self) -> str:
        raw = str(self.website or "").strip()
        if raw and raw.lower() not in {"mywebsite.com", "example.com", "localhost"}:
            host = raw
        else:
            host = str(getattr(self, "target", "") or "").strip()
        if not host:
            return ""
        if "://" in host:
            host = urlparse(host).hostname or host
        host = host.split("/")[0].split(":")[0].strip().lower()
        return host

    def test_urls(self, urls):
        results = []
        limit = max(0, int(self.probe_limit or 0))
        for url in list(urls)[:limit]:
            try:
                text = url.decode("utf-8", "ignore") if isinstance(url, (bytes, bytearray)) else str(url)
                response = requests.get(text, allow_redirects=False, timeout=8)
                page_weight = len(response.content or b"")
                code = response.status_code
                results.append((text[:120], code, page_weight))
            except Exception as exc:
                results.append((str(url)[:120], f"err:{exc.__class__.__name__}", 0))
        return results

    def run(self):
        host = self._resolve_host()
        if not host:
            print_error("No website/host to query (set website= or module target).")
            return False

        print_info(f"Checking Wayback CDX for {host}...")
        try:
            response = requests.get(
                f"https://web.archive.org/cdx/search/cdx?url={host}/*&output=text&fl=original&collapse=urlkey",
                timeout=30,
            )
        except Exception as exc:
            print_error(f"Wayback CDX request failed: {exc}")
            return False

        if not response or response.status_code >= 400:
            print_error(f"Wayback CDX returned HTTP {getattr(response, 'status_code', '?')}")
            return False

        lines = [line for line in (response.content or b"").splitlines() if line.strip()]
        print_status(f"Found {len(lines)} archived URL key(s)")
        sample_n = max(0, int(self.max_urls or 0))
        sample = lines[:sample_n]
        if sample:
            rows = []
            for line in sample:
                text = line.decode("utf-8", "ignore") if isinstance(line, (bytes, bytearray)) else str(line)
                rows.append([text[:140]])
            print_table(["Archived URL (sample)"], rows)
        else:
            print_info("No archived URLs returned.")

        if self.probe_live and sample:
            print_info(f"Live-probing up to {self.probe_limit} archived URL(s)...")
            results = self.test_urls(sample)
            print_table(["Url", "Code", "Weight"], results)
        elif lines:
            print_info(
                f"Skipped live probing of {len(lines)} URL(s). "
                "Set probe_live=true to enable (noisy)."
            )
        print_success("Done")
        return True
