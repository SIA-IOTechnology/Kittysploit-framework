#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


def _looks_like_django_debug_page(response) -> bool:
    """Match Django's real debug/technical error pages, not generic 'debug' text."""
    if not response:
        return False

    content = (response.text or "").lower()
    status = getattr(response, "status_code", 0)

    strong_markers = [
        "you're seeing this error because you have <code>debug = true</code>",
        "you're seeing this error because you have debug = true",
        "using the urlconf defined in",
        "django tried these url patterns",
        "the current path, <code>",
        "page not found <span>(404)</span>",
        "exception type:",
        "exception value:",
        "traceback <span>",
        "request method:",
        "request url:",
        "raised during:",
        "django version:",
        "python executable:",
        "python path:",
        "server time:",
        "wsgirequest:",
        "settings</th>",
    ]
    score = sum(1 for marker in strong_markers if marker in content)

    # 404 debug pages and 500 technical tracebacks use different wording.
    if status == 404 and score >= 3:
        return True
    if status >= 500 and score >= 4:
        return True

    return False


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Django Debug Mode detection',
        'description': 'Detects if Django debug mode is enabled on the target, which may lead to information disclosure or RCE.',
        'author': 'KittySploit Team',
        'severity': 'high',
        'modules': ['exploits/http/django_debug_rce'],
        'tags': ['web', 'scanner', 'django', 'debug', 'rce'],
    }

    def run(self):
        try:
            # Trigger an error to check for debug page
            response = self.http_request(
                method="GET",
                path="/nonexistent-page-that-should-404-for-django-debug-check/",
                allow_redirects=False
            )
            
            if _looks_like_django_debug_page(response):
                self.set_info(severity="high", reason="Django debug mode is enabled")
                return True
            
            return False
        except Exception:
            return False
