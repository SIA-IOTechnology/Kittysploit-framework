#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HTTP Detectors - Helpers pour détecter des technologies HTTP/Web
"""

import re
from typing import Optional


def detect_apache(response) -> Optional[str]:
    """Détecte Apache et retourne la version, ou None"""
    if not response or not hasattr(response, 'headers'):
        return None
    server = response.headers.get('Server', '')
    match = re.search(r'Apache/([\d.]+)', server, re.IGNORECASE)
    return match.group(1) if match else None


def detect_nginx(response) -> Optional[str]:
    """Détecte Nginx et retourne la version, ou None"""
    if not response or not hasattr(response, 'headers'):
        return None
    server = response.headers.get('Server', '')
    match = re.search(r'nginx/([\d.]+)', server, re.IGNORECASE)
    return match.group(1) if match else None


def detect_wordpress(response) -> bool:
    """Détecte WordPress, retourne True si trouvé"""
    if not response:
        return False
    
    # Headers
    if hasattr(response, 'headers'):
        generator = response.headers.get('X-Powered-By', '')
        if 'wordpress' in generator.lower():
            return True
    
    # Body
    if hasattr(response, 'text'):
        text = response.text.lower()
        if any(marker in text for marker in [
            'wp-content', 'wp-includes', 'wordpress', '/wp-admin/', 'wp-json'
        ]):
            return True
    
    return False


def detect_php(response) -> Optional[str]:
    """Détecte PHP et retourne la version, ou None"""
    if not response or not hasattr(response, 'headers'):
        return None
    
    powered_by = response.headers.get('X-Powered-By', '')
    match = re.search(r'PHP/([\d.]+)', powered_by, re.IGNORECASE)
    if match:
        return match.group(1)
    
    server = response.headers.get('Server', '')
    match = re.search(r'PHP/([\d.]+)', server, re.IGNORECASE)
    return match.group(1) if match else None


def detect_joomla(response) -> bool:
    """Détecte Joomla, retourne True si trouvé"""
    if not response or not hasattr(response, 'text'):
        return False
    
    text = response.text.lower()
    return any(marker in text for marker in [
        'joomla', '/media/jui/', '/administrator/', 'option=com_', 'com_content'
    ])


def detect_drupal(response) -> bool:
    """Détecte Drupal, retourne True si trouvé"""
    if not response:
        return False
    
    # Headers
    if hasattr(response, 'headers'):
        generator = response.headers.get('X-Generator', '')
        if 'drupal' in generator.lower():
            return True
    
    # Body
    if hasattr(response, 'text'):
        text = response.text.lower()
        if any(marker in text for marker in [
            'drupal', '/sites/default/', 'drupal.js', 'Drupal.settings'
        ]):
            return True
    
    return False


def php_stack_likely(response) -> bool:
    """True when headers/body strongly suggest PHP — not a Node/Next.js stack."""
    if not response or not hasattr(response, "headers"):
        return False
    xpb = (response.headers.get("X-Powered-By") or "").lower()
    if any(
        marker in xpb
        for marker in ("php", "laravel", "symfony", "cakephp", "zend", "yii", "wordpress")
    ):
        return True
    hdr = str(response.headers).lower()
    if "phpsessid" in hdr or "php_sess" in hdr:
        return True
    snippet = (getattr(response, "text", None) or "")[:20000]
    if "<?php" in snippet:
        return True
    return False


def evidence_nextjs(response) -> Optional[str]:
    """Return 'Next.js' only when response shows credible Next.js signals."""
    if not response or php_stack_likely(response) or detect_wordpress(response):
        return None

    powered = (response.headers.get("X-Powered-By") or "").lower()
    body = getattr(response, "text", None) or ""
    body_lower = body[:50000].lower()

    if "next.js" in powered or "nextjs" in powered:
        return "Next.js"
    if "__next_data__" in body_lower or "__next_f" in body_lower:
        return "Next.js"
    if "/_next/static/" in body_lower or 'id="__next_data__"' in body_lower:
        return "Next.js"
    if re.search(r"/_next/data/[^\"'\s>]+", body_lower):
        return "Next.js"
    return None


def is_nextjs(response) -> bool:
    return evidence_nextjs(response) == "Next.js"


def evidence_react(response) -> Optional[str]:
    """
    Return a React SPA label when the response looks like CRA/Vite/React
    without Next.js markers. Prefer classify_spa_stack() for Next vs React.
    """
    if not response or php_stack_likely(response) or detect_wordpress(response):
        return None
    if is_nextjs(response):
        return None

    body = getattr(response, "text", None) or ""
    body_lower = body[:80000].lower()

    # Vite React
    if "/@vite/client" in body_lower or "/@react-refresh" in body_lower:
        return "React (Vite)"
    if re.search(r"/assets/index-[a-z0-9_-]+\.js", body_lower):
        if "react" in body_lower or 'id="root"' in body_lower or "id='root'" in body_lower:
            return "React (Vite)"

    # Create React App / webpack SPA
    cra_markers = (
        "/static/js/main.",
        "/static/js/bundle.js",
        "/static/js/runtime-main.",
        "asset-manifest.json",
    )
    if any(m in body_lower for m in cra_markers):
        return "React (CRA)"

    classic = (
        "data-reactroot",
        "data-reactid",
        "__react_devtools_global_hook__",
        "react-dom.production",
        "react-dom.development",
        "react.production.min.js",
        "react.development.js",
    )
    if any(m in body_lower for m in classic):
        return "React"

    # Root mount + react chunk hint
    if ('id="root"' in body_lower or "id='root'" in body_lower) and (
        "react" in body_lower or "/static/js/" in body_lower or "/assets/" in body_lower
    ):
        return "React"

    return None


def is_react(response) -> bool:
    return evidence_react(response) is not None


def classify_spa_stack(response) -> str:
    """
    Distinguish Next.js from standalone React SPAs.

    Returns one of: nextjs | react_cra | react_vite | react | none
    """
    if is_nextjs(response):
        return "nextjs"
    label = evidence_react(response) or ""
    low = label.lower()
    if "vite" in low:
        return "react_vite"
    if "cra" in low:
        return "react_cra"
    if label:
        return "react"
    return "none"


def has_header(response, header_name: str, value_pattern: str = None) -> bool:
    """Vérifie si un header existe et correspond optionnellement à un pattern"""
    if not response or not hasattr(response, 'headers'):
        return False
    
    header_value = response.headers.get(header_name, '')
    if not header_value:
        return False
    
    if value_pattern:
        return bool(re.search(value_pattern, header_value, re.IGNORECASE))
    
    return True


def contains_pattern(response, pattern: str) -> bool:
    """Vérifie si le body contient un pattern"""
    if not response or not hasattr(response, 'text'):
        return False
    
    text = response.text.lower()
    pattern_lower = pattern.lower()
    
    # Regex ou string simple
    if any(c in pattern for c in ['(', ')', '[', ']', '.', '*', '+', '?', '^', '$']):
        return bool(re.search(pattern, text, re.IGNORECASE))
    else:
        return pattern_lower in text
