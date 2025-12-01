"""
JavaScript Encoders for KittySploit Framework

This package contains JavaScript encoders that can be used with browser_auxiliary
and browser_exploit modules to bypass XSS filters, WAF detection, and signature-based
security controls.

Available Encoders:
- charcode: Encodes JavaScript using String.fromCharCode() (recommended)
- unicode: Encodes JavaScript into Unicode escape sequences
- base64_encoder: Encodes JavaScript in base64 with atob() decoder

Usage:
    use modules/browser_auxiliary/execute_js_encoded
    set session_id <target_session>
    set code alert('XSS')
    set encoder encoders/js/charcode
    run

For more information, see modules/encoders/js/README.md
"""

__all__ = ['charcode', 'unicode', 'base64_encoder']

