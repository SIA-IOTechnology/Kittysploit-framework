from kittysploit import *
from core.framework.option.option_choice import OptChoice

class Module(Post):
    __info__ = {
        'name': 'Android Wifi Manage',
        'description': 'Manage WiFi connections on an Android device',
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

    action = OptChoice("status", "Action: status/enable/disable", True, ["status", "enable", "disable"])

    def run(self):
        try:
            action = str(self.action).strip().lower()

            if action == "enable":
                out = self.cmd_execute("svc wifi enable")
                if "permission" in (out or "").lower() or "not found" in (out or "").lower():
                    print_error("Could not enable WiFi (permission or command not available).")
                    if out:
                        print_info(out)
                    return False
                print_success("WiFi enable requested.")

            elif action == "disable":
                out = self.cmd_execute("svc wifi disable")
                if "permission" in (out or "").lower() or "not found" in (out or "").lower():
                    print_error("Could not disable WiFi (permission or command not available).")
                    if out:
                        print_info(out)
                    return False
                print_success("WiFi disable requested.")

            # status (default) or after enable/disable
            status = self.cmd_execute("cmd wifi status")
            if not status or "not connected" in status.lower():
                # Fallback for older Android versions without `cmd wifi`
                status = self.cmd_execute("dumpsys wifi")

            if not status:
                print_error("Could not retrieve WiFi status.")
                return False

            # Avoid huge dumps: truncate locally (prevents "Broken pipe" from shell piping too).
            lines = status.splitlines()
            max_lines = 120
            preview = "\n".join(lines[:max_lines])
            if len(lines) > max_lines:
                preview += f"\n... ({len(lines) - max_lines} more lines)"

            print_success("WiFi status:")
            print_info(preview)
            return True
        except Exception as e:
            print_error(f'Error: {e}')
            return False