
"""
KittyOSINT - Core Logic
"""

import sys
import os
import datetime
from typing import Dict, Any, List

# Add framework to path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from kittysploit import Framework, print_warning, print_error

class KittyOSINT:
    def __init__(self, license_key: str = None, framework: Framework = None):
        self.license_key = license_key
        self.is_pro = self._validate_license()
        # Reuse a pre-initialized framework when provided (shared DB/encryption context).
        self.framework = framework or Framework(clean_sessions=False)
        self.modules = self._load_osint_modules()
        self.scan_history = [] 

    def _validate_license(self) -> bool:
        return self.license_key and self.license_key.startswith("KOS-PRO-")

    def _load_osint_modules(self):
        """
        Loads all Auxiliary modules and filters for OSINT ones.
        """
        osint_modules = {}
        
        modules_path = os.path.join(ROOT_DIR, 'modules', 'auxiliary', 'osint')
        if not os.path.exists(modules_path):
            print_warning(f"OSINT modules directory not found: {modules_path}")
            return {}

        for filename in os.listdir(modules_path):
            if filename.endswith(".py") and not filename.startswith("__"):
                mod_name = filename[:-3]
                full_path = f"auxiliary/osint/{mod_name}"
                
                try:
                    module = self.framework.load_module(full_path)
                    if module:
                        info = self._module_info(module)
                        tags = [str(t).lower() for t in info.get('Tags', [])]
                        group = str(info.get('Group', '')).lower()
                        
                        if 'osint' in tags or group == 'osint':
                            osint_modules[mod_name] = module
                except Exception as e:
                    print_error(f"Failed to load {full_path}: {e}")
                    
        return osint_modules

    def _module_info(self, module: Any) -> Dict[str, Any]:
        """
        Normalize module metadata.
        """
        merged: Dict[str, Any] = {}

        runtime_info = getattr(module, "info", None)
        if isinstance(runtime_info, dict):
            merged.update(runtime_info)

        class_info = getattr(module.__class__, "__info__", None)
        if isinstance(class_info, dict):
            merged.update(class_info)

        get_info = getattr(module, "get_info", None)
        if callable(get_info):
            try:
                data = get_info()
                if isinstance(data, dict):
                    merged.update(data)
            except Exception:
                pass

        def pick(*keys: str, default=None):
            for key in keys:
                if key in merged and merged[key] is not None:
                    return merged[key]
            return default

        return {
            "Name": pick("Name", "name", default=getattr(module, "name", "")),
            "Description": pick("Description", "description", default=getattr(module, "description", "")),
            "Type": pick("Type", "type", default="core"),
            "Icon": pick("Icon", "icon", default="📦"),
            "Tags": pick("Tags", "tags", default=[]),
            "Group": pick("Group", "group", default=""),
        }

    def execute_module(self, module_id: str, target: str) -> Dict[str, Any]:
        if module_id not in self.modules:
            return {"error": "Module not found"}
        
        mod = self.modules[module_id]
        mod_info = self._module_info(mod)
        
        mod_type = str(mod_info.get('Type', 'core')).lower()
        if mod_type == 'pro' and not self.is_pro:
            return {"error": "PRO License Required"}
            
        try:
            if not mod.set_option('TARGET', target):
                mod.set_option('target', target)
            
            raw_data = mod.run()
            
            if raw_data is True: raw_data = {"success": True}
            elif raw_data is False: raw_data = {"error": "Module execution failed"}
            elif raw_data is None: raw_data = {}
            elif not isinstance(raw_data, dict): raw_data = {"result": raw_data}

            if "error" in raw_data:
                return {
                    "error": raw_data["error"],
                    "raw": raw_data,
                    "graph": {"nodes": [], "edges": []},
                    "meta": {"module": mod_info.get("Name", module_id), "timestamp": datetime.datetime.now().isoformat()},
                }

            nodes, edges = [], []
            if hasattr(mod, 'get_graph_nodes'):
                nodes, edges = mod.get_graph_nodes(raw_data)
            else:
                nodes = [{"id": f"{module_id}_res", "label": "Result", "group": "generic"}]
                edges = [{"from": target, "to": f"{module_id}_res", "label": "result"}]
                
            return {
                "raw": raw_data,
                "graph": {"nodes": nodes, "edges": edges},
                "meta": {"module": mod_info.get("Name", module_id), "timestamp": datetime.datetime.now().isoformat()}
            }
        except Exception as e:
            return {"error": str(e)}
