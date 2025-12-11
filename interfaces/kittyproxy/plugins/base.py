"""
Base class for interception plugins
"""

from typing import Dict, Any, Optional


class InterceptionPlugin:
    """Base class for interception plugins"""
    
    def __init__(self, name: str, description: str, enabled: bool = False):
        """
        Initialize a plugin
        
        Args:
            name: Plugin name (must be unique)
            description: Plugin description
            enabled: Whether the plugin is enabled by default
        """
        self.name = name
        self.description = description
        self.enabled = enabled
        self.config: Dict[str, Any] = {}
    
    def process_request(self, flow) -> bool:
        """
        Process a request flow.
        
        Args:
            flow: mitmproxy flow object representing the request
            
        Returns:
            True if the request should be blocked, False otherwise
        """
        return False
    
    def process_response(self, flow):
        """
        Process a response flow.
        
        Args:
            flow: mitmproxy flow object representing the response
        """
        pass
    
    def on_enable(self):
        """Called when the plugin is enabled"""
        pass
    
    def on_disable(self):
        """Called when the plugin is disabled"""
        pass

