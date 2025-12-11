"""
Template for creating a new KittyProxy plugin

Copy this file and modify it to create your own plugin.
"""

from .base import InterceptionPlugin


class MyCustomPlugin(InterceptionPlugin):
    """
    Template plugin - replace with your own implementation
    
    This is a template that you can copy and modify to create
    your own interception plugin.
    """
    
    def __init__(self):
        super().__init__(
            "My Custom Plugin",  # Change this to your plugin name
            "Description of what your plugin does"  # Change this description
        )
        # Set default enabled state (True or False)
        self.enabled = False
        
        # Define your plugin's configuration
        self.config = {
            "option1": "default_value",
            "option2": [],
            "option3": {}
        }
    
    def process_request(self, flow) -> bool:
        """
        Process a request flow.
        
        This method is called for every intercepted request.
        
        Args:
            flow: mitmproxy flow object representing the request
            
        Returns:
            True if the request should be blocked, False otherwise
        """
        if not self.enabled:
            return False
        
        # TODO: Implement your request processing logic here
        # Example:
        # if some_condition:
        #     return True  # Block the request
        
        return False
    
    def process_response(self, flow):
        """
        Process a response flow.
        
        This method is called for every intercepted response.
        
        Args:
            flow: mitmproxy flow object representing the response
        """
        if not self.enabled:
            return
        
        # TODO: Implement your response processing logic here
        # Example:
        # content = flow.response.content.decode('utf-8', errors='ignore')
        # modified_content = modify_content(content)
        # flow.response.content = modified_content.encode('utf-8')
        pass
    
    def on_enable(self):
        """
        Called when the plugin is enabled.
        Use this for initialization when the plugin is activated.
        """
        pass
    
    def on_disable(self):
        """
        Called when the plugin is disabled.
        Use this for cleanup when the plugin is deactivated.
        """
        pass

