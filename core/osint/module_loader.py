import importlib.util

class ModuleLoader:
    """
    Loads OSINT modules from the modules/osint/ directory.
    """
    
    def __init__(self, modules_dir="modules/osint"):
        self.modules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', modules_dir))
        self.modules = {}
        
    def discover_modules(self):
        """
        Scans the directory for .py files and loads them.
        """
        if not os.path.exists(self.modules_dir):
            print_error(f"Modules directory not found: {self.modules_dir}")
            return {}
            
        for filename in os.listdir(self.modules_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                mod_name = filename[:-3]
                try:
                    spec = importlib.util.spec_from_file_location(mod_name, os.path.join(self.modules_dir, filename))
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Check if it has the required class
                    if hasattr(module, 'OSINTModule'):
                        instance = module.OSINTModule()
                        self.modules[instance.NAME] = instance
                        # print_info(f"Loaded module: {instance.DISPLAY_NAME} ({instance.NAME})")
                except Exception as e:
                    print_error(f"Failed to load module {filename}: {e}")
                    
        return self.modules

    def get_module(self, name):
        return self.modules.get(name)

    def list_all(self):
        return [{"id": m.NAME, "name": m.DISPLAY_NAME, "desc": m.DESCRIPTION, "type": m.TYPE} for m in self.modules.values()]
