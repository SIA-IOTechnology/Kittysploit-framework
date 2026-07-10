"""KittySploit PDF phone-home and obfuscation library."""

from lib.pdf.generate import (
    format_generator_slugs,
    output_path,
    run_generators,
    validate_callback_host,
)
from lib.pdf.obfuscation import ensure_scheme, inject_credit, obfuscate_pdf, validate_url_or_ip

__all__ = [
    "ensure_scheme",
    "format_generator_slugs",
    "inject_credit",
    "obfuscate_pdf",
    "output_path",
    "run_generators",
    "validate_callback_host",
    "validate_url_or_ip",
]
