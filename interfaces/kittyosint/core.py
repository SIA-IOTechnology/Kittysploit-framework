
"""
KittyOSINT - Core Logic
"""

import sys
import os
import datetime
import ipaddress
import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Set

# Add framework to path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from kittysploit import Framework, print_warning, print_error

EMAIL_RX = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
DOMAIN_RX = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$",
    re.I,
)

MODULE_TARGET_COMPATIBILITY: Dict[str, Set[str]] = {
    "advanced_exposed_credentials_detector": {"domain", "email", "keyword", "url"},
    "asn_network_profile": {"domain", "ip", "url"},
    "attack_path_prioritizer": {"domain", "email", "keyword"},
    "breach_exposure_score": {"domain", "email"},
    "cloud_misconfig_exposure_detector": {"domain", "ip", "keyword", "url"},
    "domain_crtsh": {"domain"},
    "domain_dns": {"domain"},
    "domain_surface_mapper": {"domain"},
    "domain_whois": {"domain"},
    "email_infra_pivot": {"domain"},
    "hidden_metadata_hunter": {"file", "url"},
    "identity_exposure_graph": {"domain", "email", "keyword"},
    "identity_handle_hunter": {"domain", "email", "keyword"},
    "ip_geolocation": {"domain", "ip", "url"},
    "ip_reverse_dns": {"ip"},
    "js_endpoint_extractor": {"domain", "ip", "url"},
    "mail_security_posture": {"domain"},
    "public_bucket_hunter": {"domain"},
    "saas_tenant_discovery": {"domain"},
    "secret_leak_access_validator": {"domain", "file", "ip", "keyword", "url"},
    "shadow_asset_business_mapper": {"domain"},
    "ssl_tls_certificate_change_tracker": {"domain"},
    "subdomain_takeover_hint": {"domain"},
    "terraform_state_exposure_detector": {"domain", "keyword", "url"},
    "typosquat_detector": {"domain"},
    "url_headers": {"domain", "ip", "url"},
    "webhook_api_leak_analyzer": {"domain", "ip", "url"},
}

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

    def _classify_host(self, value: str) -> str:
        host = str(value or "").strip().lower().rstrip(".")
        if not host:
            return "keyword"
        try:
            ipaddress.ip_address(host)
            return "ip"
        except Exception:
            pass
        if DOMAIN_RX.match(host):
            return "domain"
        return "keyword"

    def classify_target(self, target: str) -> Dict[str, Any]:
        raw = str(target or "").strip()
        if not raw:
            return {"kind": "empty", "host": "", "host_kind": "empty", "accepted_kinds": set()}

        accepted_kinds: Set[str] = set()
        if os.path.exists(raw):
            accepted_kinds.add("file")
        if EMAIL_RX.match(raw):
            accepted_kinds.add("email")

        host = ""
        host_kind = "keyword"
        if raw.startswith(("http://", "https://")):
            accepted_kinds.add("url")
            parsed = urlparse(raw)
            host = (parsed.hostname or "").strip().lower().rstrip(".")
            host_kind = self._classify_host(host)
            if host_kind in ("domain", "ip"):
                accepted_kinds.add(host_kind)
        else:
            host = raw.strip().lower().rstrip(".")
            host_kind = self._classify_host(host)
            accepted_kinds.add(host_kind)

        if not accepted_kinds:
            accepted_kinds.add("keyword")

        kind = "keyword"
        for preferred in ("file", "email", "url", "domain", "ip", "keyword"):
            if preferred in accepted_kinds:
                kind = preferred
                break

        return {
            "kind": kind,
            "host": host,
            "host_kind": host_kind,
            "accepted_kinds": accepted_kinds,
        }

    def module_supported_target_types(self, module_id: str, module: Any = None) -> List[str]:
        if module_id in MODULE_TARGET_COMPATIBILITY:
            return sorted(MODULE_TARGET_COMPATIBILITY[module_id])

        mod = module or self.modules.get(module_id)
        if mod is None:
            return ["domain", "email", "ip", "keyword", "url"]

        if hasattr(mod, "query") and not hasattr(mod, "target"):
            return ["domain", "email", "keyword"]

        info = self._module_info(mod)
        blob = " ".join(
            [
                str(info.get("Name", "")),
                str(info.get("Description", "")),
                " ".join([str(t) for t in info.get("Tags", []) or []]),
            ]
        ).lower()

        if "file path" in blob or "file url" in blob:
            return ["file", "url"]
        if "ip address" in blob:
            return ["ip"]
        if "target url" in blob or "http" in blob or "web" in blob:
            return ["domain", "ip", "url"]
        if "email" in blob and "domain" not in blob:
            return ["email", "keyword"]
        if "domain" in blob:
            return ["domain"]
        return ["domain", "email", "ip", "keyword", "url"]

    def module_compatibility(self, module_id: str, target: str, module: Any = None) -> Dict[str, Any]:
        classification = self.classify_target(target)
        supported = set(self.module_supported_target_types(module_id, module=module))
        accepted = classification.get("accepted_kinds", set())
        compatible = bool(supported.intersection(accepted))
        effective_target = str(target or "").strip()
        effective_target_kind = classification.get("kind", "keyword")

        if classification.get("kind") == "url":
            host = classification.get("host", "")
            host_kind = classification.get("host_kind", "keyword")
            if "url" in supported:
                effective_target = str(target or "").strip()
                effective_target_kind = "url"
                compatible = True
            elif host and host_kind in supported:
                effective_target = host
                effective_target_kind = host_kind
                compatible = True
            else:
                compatible = False

        if compatible:
            return {
                "compatible": True,
                "reason": "",
                "target_kind": classification.get("kind", "keyword"),
                "effective_target": effective_target,
                "effective_target_kind": effective_target_kind,
                "supported_target_types": sorted(supported),
            }

        target_kind = classification.get("kind", "keyword")
        supported_text = ", ".join(sorted(supported))
        return {
            "compatible": False,
            "reason": f"incompatible target type '{target_kind}' (supported: {supported_text})",
            "target_kind": target_kind,
            "effective_target": effective_target,
            "effective_target_kind": effective_target_kind,
            "supported_target_types": sorted(supported),
        }

    def _set_module_seed(self, mod: Any, target: str) -> None:
        for option_name in ("TARGET", "target", "query"):
            try:
                if mod.set_option(option_name, target):
                    return
            except Exception:
                continue

    def execute_module(self, module_id: str, target: str) -> Dict[str, Any]:
        if module_id not in self.modules:
            return {"error": "Module not found"}
        
        mod = self.modules[module_id]
        mod_info = self._module_info(mod)
        compatibility = self.module_compatibility(module_id, target, module=mod)
        effective_target = compatibility.get("effective_target", target)
        
        mod_type = str(mod_info.get('Type', 'core')).lower()
        if mod_type == 'pro' and not self.is_pro:
            return {"error": "PRO License Required"}
        if not compatibility["compatible"]:
            return {
                "skipped": True,
                "reason": compatibility["reason"],
                    "raw": {
                        "skipped": True,
                        "reason": compatibility["reason"],
                        "target": target,
                        "effective_target": effective_target,
                        "target_kind": compatibility["target_kind"],
                    },
                "graph": {"nodes": [], "edges": []},
                "meta": {
                    "module": mod_info.get("Name", module_id),
                    "timestamp": datetime.datetime.now().isoformat(),
                    "supported_target_types": compatibility["supported_target_types"],
                    "target_kind": compatibility["target_kind"],
                },
            }
            
        try:
            self._set_module_seed(mod, effective_target)
            
            raw_data = mod.run()
            
            if raw_data is True: raw_data = {"success": True}
            elif raw_data is False: raw_data = {"error": "Module execution failed"}
            elif raw_data is None: raw_data = {}
            elif not isinstance(raw_data, dict): raw_data = {"result": raw_data}
            if raw_data.get("skipped"):
                return {
                    "skipped": True,
                    "reason": str(raw_data.get("reason") or "module skipped"),
                    "raw": raw_data,
                    "graph": {"nodes": [], "edges": []},
                    "meta": {
                        "module": mod_info.get("Name", module_id),
                        "timestamp": datetime.datetime.now().isoformat(),
                        "supported_target_types": compatibility["supported_target_types"],
                        "target_kind": compatibility["target_kind"],
                        "effective_target_kind": compatibility.get("effective_target_kind"),
                    },
                }

            if "error" in raw_data:
                return {
                    "error": raw_data["error"],
                    "raw": raw_data,
                    "graph": {"nodes": [], "edges": []},
                    "meta": {
                        "module": mod_info.get("Name", module_id),
                        "timestamp": datetime.datetime.now().isoformat(),
                        "supported_target_types": compatibility["supported_target_types"],
                        "target_kind": compatibility["target_kind"],
                        "effective_target_kind": compatibility.get("effective_target_kind"),
                    },
                }

            nodes, edges = [], []
            if hasattr(mod, 'get_graph_nodes'):
                nodes, edges = mod.get_graph_nodes(raw_data)
            else:
                nodes = [{"id": f"{module_id}_res", "label": "Result", "group": "generic"}]
                edges = [{"from": effective_target, "to": f"{module_id}_res", "label": "result"}]
                
            return {
                "raw": raw_data,
                "graph": {"nodes": nodes, "edges": edges},
                "meta": {
                    "module": mod_info.get("Name", module_id),
                    "timestamp": datetime.datetime.now().isoformat(),
                    "supported_target_types": compatibility["supported_target_types"],
                    "target_kind": compatibility["target_kind"],
                    "effective_target_kind": compatibility.get("effective_target_kind"),
                    "effective_target": effective_target,
                }
            }
        except Exception as e:
            return {"error": str(e)}
