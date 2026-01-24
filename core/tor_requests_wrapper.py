#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tor Requests Wrapper
Monkey-patches the requests library to automatically use Tor proxy when enabled
"""

import requests
from typing import Optional, Dict, Any
import os

# Store original requests functions
_original_request = requests.request
_original_get = requests.get
_original_post = requests.post
_original_put = requests.put
_original_delete = requests.delete
_original_head = requests.head
_original_patch = requests.patch
_original_options = requests.options

# Global Tor manager reference
_tor_manager = None


def set_tor_manager(tor_manager):
    """Set the Tor manager instance"""
    global _tor_manager
    _tor_manager = tor_manager


def _get_tor_proxies() -> Optional[Dict[str, str]]:
    """Get Tor proxy configuration if Tor is enabled"""
    if _tor_manager and _tor_manager.is_enabled():
        return _tor_manager.get_tor_proxy_dict()
    return None


def _apply_tor_proxy(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Apply Tor proxy to request kwargs if Tor is enabled and no proxy is already set"""
    # Only apply if no proxy is explicitly set
    if 'proxies' not in kwargs or not kwargs.get('proxies'):
        tor_proxies = _get_tor_proxies()
        if tor_proxies:
            kwargs['proxies'] = tor_proxies
    return kwargs


def _patched_request(method, url, **kwargs):
    """Patched requests.request that automatically uses Tor"""
    kwargs = _apply_tor_proxy(kwargs)
    return _original_request(method, url, **kwargs)


def _patched_get(url, **kwargs):
    """Patched requests.get that automatically uses Tor"""
    kwargs = _apply_tor_proxy(kwargs)
    return _original_get(url, **kwargs)


def _patched_post(url, **kwargs):
    """Patched requests.post that automatically uses Tor"""
    kwargs = _apply_tor_proxy(kwargs)
    return _original_post(url, **kwargs)


def _patched_put(url, **kwargs):
    """Patched requests.put that automatically uses Tor"""
    kwargs = _apply_tor_proxy(kwargs)
    return _original_put(url, **kwargs)


def _patched_delete(url, **kwargs):
    """Patched requests.delete that automatically uses Tor"""
    kwargs = _apply_tor_proxy(kwargs)
    return _original_delete(url, **kwargs)


def _patched_head(url, **kwargs):
    """Patched requests.head that automatically uses Tor"""
    kwargs = _apply_tor_proxy(kwargs)
    return _original_head(url, **kwargs)


def _patched_patch(url, **kwargs):
    """Patched requests.patch that automatically uses Tor"""
    kwargs = _apply_tor_proxy(kwargs)
    return _original_patch(url, **kwargs)


def _patched_options(url, **kwargs):
    """Patched requests.options that automatically uses Tor"""
    kwargs = _apply_tor_proxy(kwargs)
    return _original_options(url, **kwargs)


def install_tor_requests_wrapper(tor_manager):
    """
    Install the Tor requests wrapper to intercept all requests library calls
    
    Args:
        tor_manager: TorManager instance
    """
    global _tor_manager
    _tor_manager = tor_manager
    
    # Patch requests module functions
    requests.request = _patched_request
    requests.get = _patched_get
    requests.post = _patched_post
    requests.put = _patched_put
    requests.delete = _patched_delete
    requests.head = _patched_head
    requests.patch = _patched_patch
    requests.options = _patched_options
    
    # Also patch Session class methods
    _original_session_request = requests.Session.request
    
    def _patched_session_request(self, method, url, **kwargs):
        kwargs = _apply_tor_proxy(kwargs)
        return _original_session_request(self, method, url, **kwargs)
    
    requests.Session.request = _patched_session_request


def uninstall_tor_requests_wrapper():
    """Uninstall the Tor requests wrapper and restore original functions"""
    global _tor_manager
    _tor_manager = None
    
    # Restore original functions
    requests.request = _original_request
    requests.get = _original_get
    requests.post = _original_post
    requests.put = _original_put
    requests.delete = _original_delete
    requests.head = _original_head
    requests.patch = _original_patch
    requests.options = _original_options
    
    # Restore Session.request
    # Note: We can't easily restore the original Session.request without storing it
    # This is a limitation, but sessions created after uninstall will work correctly
