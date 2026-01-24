#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FTP Detectors - Helpers pour détecter des serveurs FTP
"""

import re
from typing import Optional


def detect_vsftpd(banner: str) -> Optional[str]:
    """Détecte vsftpd et retourne la version, ou None"""
    if not banner:
        return None
    match = re.search(r'vsFTPd ([\d.]+)', banner, re.IGNORECASE)
    return match.group(1) if match else None


def detect_proftpd(banner: str) -> Optional[str]:
    """Détecte ProFTPD et retourne la version, ou None"""
    if not banner:
        return None
    match = re.search(r'ProFTPD ([\d.]+)', banner, re.IGNORECASE)
    return match.group(1) if match else None


def detect_filezilla(banner: str) -> Optional[str]:
    """Détecte FileZilla Server et retourne la version, ou None"""
    if not banner:
        return None
    match = re.search(r'FileZilla Server ([\d.]+)', banner, re.IGNORECASE)
    return match.group(1) if match else None


def detect_pureftpd(banner: str) -> Optional[str]:
    """Détecte Pure-FTPd et retourne la version, ou None"""
    if not banner:
        return None
    match = re.search(r'Pure-FTPd ([\d.]+)', banner, re.IGNORECASE)
    return match.group(1) if match else None
