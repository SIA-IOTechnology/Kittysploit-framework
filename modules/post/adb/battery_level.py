from kittysploit import *
import re

class Module(Post):

    __info__ = {
        'name': 'Android Battery Level',
        'description': 'Get the battery level of an Android device',
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
            # Use the framework's command execution path so this works with ADB sessions.
            # This relies on ShellManager auto-creating an `android` shell for android sessions.
            dumpsys = self.cmd_execute("dumpsys battery")

            if not dumpsys or "not connected" in dumpsys.lower():
                print_error("Could not query battery info via ADB (no output / not connected).")
                return False

            # Typical output contains: "level: 73"
            m = re.search(r"(?mi)^\s*level\s*:\s*(\d+)\s*$", dumpsys)
            if not m:
                # Fallback: sometimes `level=` appears depending on vendor tooling.
                m = re.search(r"(?mi)^\s*level\s*=\s*(\d+)\s*$", dumpsys)

            if not m:
                print_error("Battery level not found in `dumpsys battery` output.")
                return False

            battery_level = int(m.group(1))
            print_success(f"Battery level: {battery_level}%")
            return True
        except Exception as e:
            print_error(f'Error: {e}')
            return False