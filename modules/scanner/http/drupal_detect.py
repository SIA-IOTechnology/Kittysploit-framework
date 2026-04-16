#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Drupal detection',
        'description': 'Detects if Drupal is installed on the target.',
        'author': 'KittySploit Team',
        'severity': 'info',
        'modules': [],
        'tags': ['web', 'scanner', 'drupal', 'cms'],
    }

    def run(self):
        score = 0

        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r:
            return False

        body = (r.text or "").lower()
        headers = str(r.headers).lower()

        # Strong indicators on homepage.
        if re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*drupal', body, re.IGNORECASE):
            score += 4
        if "drupal.settings" in body or "drupalsettings" in body:
            score += 3
        if "/sites/default/files/" in body or "/sites/all/" in body:
            score += 3
        if "/core/assets/" in body:
            score += 2

        # Weak indicator.
        if "drupal" in body or "drupal" in headers:
            score += 1

        # Validate user login page with stricter patterns.
        r2 = self.http_request(method="GET", path="/user/login", allow_redirects=False)
        if r2 and r2.status_code in [200, 301, 302, 403]:
            login_body = (r2.text or "").lower()
            location = (r2.headers.get("Location", "") or "").lower()
            if (
                "form_id=\"user_login_form\"" in login_body
                or "name=\"form_id\" value=\"user_login_form\"" in login_body
                or "/user/login" in location
                or "drupal" in login_body
            ):
                score += 4

        return score >= 5
