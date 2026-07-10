from kittysploit import *

class Module(Post):

    __info__ = {
        'name': 'Android Reboot',
        'description': 'Reboot an Android device',
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
            out = self.cmd_execute("reboot")
            
            if not out or "not connected" in (out or "").lower():
                print_error("Could not reboot device via ADB (no output / not connected).")
                return False
            
            # reboot typically returns immediately (device reboots)
            # Check for permission errors
            if "permission" in out.lower() or "denied" in out.lower():
                print_error("Permission denied: Cannot reboot device (requires root or appropriate privileges).")
                if out:
                    print_info(out)
                return False
            
            print_success("Reboot requested. Device should reboot shortly.")
            print_warning("Note: This will disconnect the ADB session.")
            return True
        except Exception as e:
            print_error(f'Error: {e}')
            return False