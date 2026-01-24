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


def detect_version(response, pattern: str) -> Optional[str]:
    """Détecte une version avec un pattern regex"""
    if not response:
        return None
    
    # Headers
    if hasattr(response, 'headers'):
        for header_value in response.headers.values():
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                return match.group(1)
    
    # Body
    if hasattr(response, 'text'):
        match = re.search(pattern, response.text, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None


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
