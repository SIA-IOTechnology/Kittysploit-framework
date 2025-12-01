from typing import Dict, Any, Optional

class Demo:
    """Base class for all demo modules"""
    
    NAME = "Base Demo Module"
    DESCRIPTION = "Base class for demo modules"
    OPTIONS: Dict[str, Dict[str, Any]] = {}
    
    def __init__(self):
        self.options = {}
        # Initialize options with default values
        for opt_name, opt_info in self.OPTIONS.items():
            if 'default' in opt_info:
                self.options[opt_name] = opt_info['default']
    
    def validate_options(self) -> bool:
        """Validate that all required options are set"""
        for opt_name, opt_info in self.OPTIONS.items():
            if opt_info.get('required', False) and opt_name not in self.options:
                return False
        return True
    
    def set_option(self, option: str, value: Any) -> bool:
        """Set an option value"""
        if option not in self.OPTIONS:
            return False
            
        # Validate value type if specified
        opt_type = self.OPTIONS[option].get('type')
        if opt_type:
            try:
                value = opt_type(value)
            except:
                return False
                
        # Validate choices if specified
        choices = self.OPTIONS[option].get('choices')
        if choices and value not in choices:
            return False
            
        self.options[option] = value
        return True
    
    def get_options(self) -> Dict[str, Any]:
        """Get current option values"""
        return self.options
    
    def get_info(self) -> Dict[str, Any]:
        """Get module information"""
        return {
            'name': self.NAME,
            'description': self.DESCRIPTION,
            'options': self.OPTIONS
        }
    
    def run(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run the demo module. Must be implemented by subclasses."""
        raise NotImplementedError("Demo modules must implement run()") 