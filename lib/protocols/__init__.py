#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Protocol libraries for KittySploit
"""

# Import protocol clients
__all__ = []

try:
    from .http.http_client import Http_client
    __all__.append('Http_client')
except ImportError:
    pass

try:
    from .http.websocket_client import WebSocket_client
    __all__.append('WebSocket_client')
except ImportError:
    pass
