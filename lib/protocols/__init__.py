#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Protocol libraries for KittySploit
"""

# Import only existing modules
try:
    from .http_client import HTTPClient
    __all__ = ['HTTPClient']
except ImportError:
    __all__ = []
