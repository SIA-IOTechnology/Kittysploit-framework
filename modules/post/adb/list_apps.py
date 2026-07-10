from kittysploit import *
import re

class Module(Post):
    __info__ = {
        'name': 'Android List Apps',
        'description': 'List all apps on an Android device',
        'author': 'KittySploit Team',
        'session_type': SessionType.ANDROID,
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['risk_signals'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }
    def run(self):
        try:
            # Use ADB via cmd_execute (requires an android shell auto-created for android sessions).
            # `pm list packages` is available on most Android builds.
            out = self.cmd_execute("pm list packages")

            if not out or "not connected" in out.lower():
                print_error("Could not list packages via ADB (no output / not connected).")
                return False

            # Typical output: "package:com.example.app"
            pkgs = re.findall(r"(?mi)^\s*package:([^\s]+)\s*$", out)
            if not pkgs:
                # Fallback: print raw output
                print_success("Apps (raw):")
                print_info(out)
                return True

            pkgs = sorted(set(p.strip() for p in pkgs if p.strip()))
            print_success(f"Apps ({len(pkgs)}):")
            for p in pkgs[:300]:
                print_info(f"  {p}")
            return True
        except Exception as e:
            print_error(f'Error: {e}')
            return False