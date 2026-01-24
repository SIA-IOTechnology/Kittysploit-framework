#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Router Detectors - Helpers pour détecter des routeurs et équipements réseau
"""

import re
from typing import Optional


def detect_dlink(response) -> Optional[str]:
    """Détecte un routeur D-Link et retourne le modèle/version, ou None"""
    if not response:
        return None
    
    # Headers
    if hasattr(response, 'headers'):
        server = response.headers.get('Server', '')
        match = re.search(r'D-Link|DIR-(\w+)', server, re.IGNORECASE)
        if match:
            return match.group(1) if match.groups() else 'D-Link'
    
    # Body
    if hasattr(response, 'text'):
        text = response.text.lower()
        if 'd-link' in text or 'dlink' in text:
            match = re.search(r'dir-?(\w+)', text, re.IGNORECASE)
            return match.group(1) if match else 'D-Link'
    
    return None


def detect_tplink(response) -> bool:
    """Détecte un routeur TP-Link, retourne True si trouvé"""
    if not response:
        return False
    
    if hasattr(response, 'text'):
        text = response.text.lower()
        return any(marker in text for marker in [
            'tp-link', 'tplink', 'tp link', 'tplogin'
        ])
    
    return False


def detect_netgear(response) -> bool:
    """Détecte un routeur Netgear, retourne True si trouvé"""
    if not response:
        return False
    
    if hasattr(response, 'text'):
        text = response.text.lower()
        return 'netgear' in text or 'genie' in text
    
    return False


def detect_cisco(response) -> Optional[str]:
    """Détecte un équipement Cisco et retourne la version, ou None"""
    if not response:
        return None
    
    # Headers
    if hasattr(response, 'headers'):
        server = response.headers.get('Server', '')
        match = re.search(r'Cisco-([\w-]+)', server, re.IGNORECASE)
        if match:
            return match.group(1)
    
    # Body
    if hasattr(response, 'text'):
        text = response.text.lower()
        if 'cisco' in text:
            match = re.search(r'cisco ([\w.]+)', text, re.IGNORECASE)
            return match.group(1) if match else 'Cisco'
    
    return None
