#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'robots.txt / sitemap detection',
        'description': 'Detects exposed robots.txt and sitemap references; reports interesting paths.',
        'author': 'KittySploit Team',
        'severity': 'info',
        'modules': [],
        'tags': ['web', 'scanner', 'robots', 'sitemap', 'disclosure', 'enumeration'],
    }

    def run(self):
        r = self.http_request(method="GET", path="/robots.txt", allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        text = r.text
        if "user-agent" not in text.lower() and "disallow" not in text.lower() and "allow" not in text.lower():
            return False
        details = []
        lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        disallow_paths = []
        sitemaps = []
        for line in lines:
            lower = line.lower()
            if lower.startswith("disallow:") and len(line) > 9:
                path = line[9:].strip()
                if path and path != "/":
                    disallow_paths.append(path)
            elif lower.startswith("sitemap:") and len(line) > 8:
                sitemaps.append(line[8:].strip())
        if disallow_paths:
            details.append("Disallow: " + ", ".join(disallow_paths[:10]))
        if sitemaps:
            details.append("Sitemap(s): " + ", ".join(sitemaps[:5]))
        reason = "robots.txt exposed" + ("; " + "; ".join(details) if details else "")
        self.set_info(severity="info", reason=reason)
        return True
