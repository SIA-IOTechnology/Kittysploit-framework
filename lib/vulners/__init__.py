"""Vulners API client and feed export helpers for KittySploit."""

from lib.vulners.client import (
    PLUGIN_VERSION,
    VulnersClient,
    VulnersError,
    bulletin_display_title,
    exploits_query_for_cves,
    normalize_bulletin,
)
from lib.vulners.feed import (
    GITHUB_MODULE_HREF_BASE,
    build_module_bulletin,
    iter_feed_bulletins,
    module_path_to_vulners_id,
)

__all__ = [
    "PLUGIN_VERSION",
    "VulnersClient",
    "VulnersError",
    "bulletin_display_title",
    "exploits_query_for_cves",
    "normalize_bulletin",
    "GITHUB_MODULE_HREF_BASE",
    "build_module_bulletin",
    "iter_feed_bulletins",
    "module_path_to_vulners_id",
]
