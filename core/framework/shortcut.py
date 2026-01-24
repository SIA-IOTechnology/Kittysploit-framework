from core.framework.base_module import BaseModule
from core.output_handler import print_info, print_success, print_error

class Shortcut(BaseModule):

    TYPE_MODULE = "shortcut"

    def __init__(self, framework=None):
        super(Shortcut, self).__init__(framework)
        self.current_module = None

    def run(self):
        """Run the shortcut"""
        raise NotImplementedError("Shortcut modules must implement the run() method")
    
    def check(self):
        """Check if the shortcut can be executed"""
        raise NotImplementedError("Shortcut modules must implement the check() method")
    
    def get_info(self):
        """Get the information about the shortcut"""
        return {
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "references": self.references,
            "requires_root": self.requires_root,
            "options": self.options
        }
    
    def load_module(self, module_path):
        """Load the module"""
        module = self.framework.load_module(module_path)
        if module:
            self.current_module = module
            return True
        return False
    
    def unload_module(self):
        """Unload the module"""
        self.current_module = None
        return True
    
    def get_current_module(self):
        """Get the current module"""
        return self.current_module
    
    def get_current_module_name(self):
        """Get the name of the current module"""
        return self.current_module.name
    
    def execute(self):
        self.current_module.run()
    
    def add_option(self, name, value):
        """Add an option to the current module"""
        setattr(self.current_module, name, value)
        self.current_module.exploit_attributes[name][0] = value
        return True
    
    def remove_option(self, name):
        """Remove an option from the current module"""
        delattr(self.current_module, name)
        del self.current_module.exploit_attributes[name]
        return True
    
    def get_option(self, name):
        """Get an option from the current module"""
        return getattr(self.current_module, name)