"""
URL Blocklist Plugin

Block requests matching URL patterns (blacklist/whitelist).
"""

import re
from .base import InterceptionPlugin


class URLBlocklistPlugin(InterceptionPlugin):
    """Plugin to block requests matching URL patterns"""
    
    def __init__(self):
        super().__init__(
            "URL Blocklist",
            "Block requests matching URL patterns"
        )
        self.config = {
            "block_patterns": [],
            "allow_patterns": []
        }
    
    def process_request(self, flow) -> bool:
        if not self.enabled:
            return False
        
        url = flow.request.url
        
        # Check allow patterns first (whitelist)
        for pattern in self.config.get("allow_patterns", []):
            if re.search(pattern, url, re.IGNORECASE):
                return False
        
        # Check block patterns (blacklist)
        for pattern in self.config.get("block_patterns", []):
            if re.search(pattern, url, re.IGNORECASE):
                return True  # Block this request
        
        return False

