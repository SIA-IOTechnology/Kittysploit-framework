#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PATHS_TO_CHECK = ["/", "/images/", "/img/", "/assets/", "/static/", "/backup/", "/uploads/", "/files/", "/media/"]


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Directory listing detection',
        'description': 'Detects if directory listing is enabled on the server.',
        'author': 'KittySploit Team',
        'severity': 'low',
        'modules': [],
        'tags': ['web', 'scanner', 'directory', 'listing', 'disclosure'],
    }

    def run(self):
        found = []
        for path in PATHS_TO_CHECK:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            t = r.text
            if "index of" in t.lower() or "directory listing" in t.lower() or ("<title>" in t.lower() and "index of" in t.lower()):
                found.append(path.rstrip("/") or "/")
        if found:
            self.set_info(severity="low", reason=f"Listing enabled: {', '.join(found)}")
            return True
        return False
