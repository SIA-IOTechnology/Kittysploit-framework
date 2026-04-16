#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re


def _extract_wordpress_version(text: str) -> str:
    """Parse version from homepage HTML or feed XML."""
    if not text:
        return ""
    # <meta name="generator" content="WordPress 6.x" /> (attribute order variants)
    for pat in (
        r'<meta[^>]+name\s*=\s*["\']generator["\'][^>]+content\s*=\s*["\']WordPress\s+([\d.]+)',
        r'<meta[^>]+content\s*=\s*["\']WordPress\s+([\d.]+)["\'][^>]+name\s*=\s*["\']generator["\']',
    ):
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    # RSS/Atom only: avoid matching random wordpress.org/?v=2 cache-bust links in HTML
    m = re.search(
        r"<generator[^>]*>\s*https?://wordpress\.org/\?v=([\d.]+)\s*</generator>",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if m:
        return m.group(1).strip()
    return ""


def _version_from_readme_html(text: str) -> str:
    """
    readme.html includes 'GNU ... Version 2' (GPL) before the core version line.
    Only match the official WordPress line, not bare 'Version 2'.
    """
    if not text:
        return ""
    m = re.search(
        r"WordPress\s*</a>\s*Version\s+([\d.]+)",
        text,
        re.IGNORECASE,
    )
    if m:
        return m.group(1).strip()
    m = re.search(
        r'(?:id|class)\s*=\s*["\']wp-version["\'][^>]*>.*?Version\s+([\d.]+)',
        text,
        re.IGNORECASE | re.DOTALL,
    )
    return m.group(1).strip() if m else ""


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'WordPress detection',
        'description': 'Detects if WordPress is installed on the target.',
        'author': 'KittySploit Team',
        'severity': 'info',
        'modules': [],
        'tags': ['web', 'scanner', 'wordpress', 'cms'],
        'agent': {
            'requires': {
                'min_endpoints': 0,
                'min_params': 0,
            },
            'produces': ['tech_hints', 'specializations', 'risk_signals'],
            'cost': 'low',
            'noise': 'low',
            'value': 'high',
        },
    }

    def run(self):
        score = 0

        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r:
            return False

        raw_home = r.text or ""
        body = raw_home.lower()
        headers = str(r.headers).lower()

        # Strong indicators on homepage.
        if re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*wordpress', body, re.IGNORECASE):
            score += 4
        if "/wp-content/themes/" in body or "/wp-content/plugins/" in body:
            score += 3
        if "/wp-includes/" in body:
            score += 3
        if "/xmlrpc.php" in body:
            score += 2

        # Weak indicator (can appear in unrelated text).
        if "wordpress" in body or "wordpress" in headers:
            score += 1

        # Validate wp-login page with stricter patterns.
        r2 = self.http_request(method="GET", path="/wp-login.php", allow_redirects=True)
        if r2 and r2.status_code in [200, 301, 302, 403]:
            login_body = (r2.text or "").lower()
            location = (r2.headers.get("Location", "") or "").lower()

            if (
                "wp-submit" in login_body
                or "user_login" in login_body
                or "id=\"loginform\"" in login_body
                or "lost your password?" in login_body
                or "wp-login.php" in location
            ):
                score += 4

        # Validate wp-admin behavior.
        r3 = self.http_request(method="GET", path="/wp-admin/", allow_redirects=False)
        if r3 and r3.status_code in [301, 302]:
            location = (r3.headers.get("Location", "") or "").lower()
            if "wp-login.php" in location:
                score += 3

        # Reduce false positives: require either one strong login/admin proof
        # or enough cumulative indicators.
        if score < 5:
            return False

        version = _extract_wordpress_version(raw_home)
        if not version:
            r_readme = self.http_request(method="GET", path="/readme.html", allow_redirects=True)
            if r_readme and r_readme.status_code == 200:
                readme_txt = r_readme.text or ""
                version = _version_from_readme_html(readme_txt) or _extract_wordpress_version(readme_txt)
        if not version:
            r_feed = self.http_request(method="GET", path="/feed/", allow_redirects=True)
            if r_feed and r_feed.status_code == 200:
                version = _extract_wordpress_version(r_feed.text or "")

        self.set_info(version=version or "unknown")
        return True
