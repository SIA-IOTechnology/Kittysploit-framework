from kittysploit import *
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin


class Module(Post, System, LinuxSessionMixin):
    __info__ = {
        "name": "Linux Service Controller",
        "description": "Manage Linux services (status, start, stop, restart, enable, disable)",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    service = OptString("", "Service name (e.g. ssh, nginx, apache2)", True)
    action = OptChoice(
        "status",
        "Action to perform",
        False,
        choices=["status", "start", "stop", "restart", "enable", "disable"],
    )

    def _run_cmd(self, command: str) -> str:
        try:
            output = self.linux_execute("{cmd} 2>&1".format(cmd=command))
            return output.strip() if output else ""
        except Exception:
            return ""

    def _has_permission_issue(self, output: str) -> bool:
        lowered = (output or "").lower()
        return "permission denied" in lowered or "access denied" in lowered or "not permitted" in lowered

    def _print_result(self, action: str, service: str, output: str):
        if output:
            if self._has_permission_issue(output):
                print_warning("Operation may require elevated privileges")
            print_info(output)
        print_success(f"Service action executed: {action} {service}")

    def run(self):

        if not self.linux_require_linux():
            return False

        service = str(self.service or "").strip()
        if not service:
            print_error("service option is required")
            return False

        action = str(self.action or "status").strip().lower()
        print_status(f"Managing service '{service}' with action '{action}'")

        if self.command_exists("systemctl"):
            if action == "status":
                cmd = "systemctl status {svc} --no-pager".format(svc=service)
            else:
                cmd = "systemctl {act} {svc}".format(act=action, svc=service)
            output = self._run_cmd(cmd)
            self._print_result(action, service, output)
            return True

        if self.command_exists("service"):
            if action in ("enable", "disable"):
                print_warning("enable/disable not supported with legacy 'service' command")
                return False
            cmd = "service {svc} {act}".format(svc=service, act=action)
            output = self._run_cmd(cmd)
            self._print_result(action, service, output)
            return True

        print_error("Neither systemctl nor service is available on target")
        return False
