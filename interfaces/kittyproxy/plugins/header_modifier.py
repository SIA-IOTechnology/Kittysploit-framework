"""
Header Modifier Plugin

Automatically modify request headers (add, remove, or modify).
"""

from .base import InterceptionPlugin


class HeaderModifierPlugin(InterceptionPlugin):
    """Plugin to modify headers automatically"""
    
    def __init__(self):
        super().__init__(
            "Header Modifier",
            "Automatically modify request headers"
        )
        self.config = {
            "add_headers": {},
            "remove_headers": [],
            "modify_headers": {}
        }
    
    def process_request(self, flow) -> bool:
        if not self.enabled:
            return False
        
        # Add headers
        for key, value in self.config.get("add_headers", {}).items():
            flow.request.headers[key] = value
        
        # Remove headers
        for header in self.config.get("remove_headers", []):
            if header in flow.request.headers:
                del flow.request.headers[header]
        
        # Modify headers
        for key, value in self.config.get("modify_headers", {}).items():
            if key in flow.request.headers:
                flow.request.headers[key] = value
        
        return False

