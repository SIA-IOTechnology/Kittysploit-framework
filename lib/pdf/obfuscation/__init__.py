"""PDF obfuscation and metadata helpers."""

from lib.pdf.obfuscation.core import (
    ensure_scheme,
    inject_credit,
    obfuscate_pdf,
    validate_url_or_ip,
)

__all__ = [
    "ensure_scheme",
    "inject_credit",
    "obfuscate_pdf",
    "validate_url_or_ip",
]
