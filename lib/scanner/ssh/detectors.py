#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSH Detectors - Helpers pour détecter des serveurs SSH
"""

import re
from typing import Optional


def detect_openssh(banner: str) -> Optional[str]:
    """Détecte OpenSSH et retourne la version, ou None"""
    if not banner:
        return None
    match = re.search(r'OpenSSH[_-]([\d.]+)', banner, re.IGNORECASE)
    return match.group(1) if match else None


def detect_dropbear(banner: str) -> Optional[str]:
    """Détecte Dropbear SSH et retourne la version, ou None"""
    if not banner:
        return None
    match = re.search(r'dropbear_([\d.]+)', banner, re.IGNORECASE)
    return match.group(1) if match else None
