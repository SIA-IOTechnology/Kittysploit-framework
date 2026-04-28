from kittysploit import *
from lib.post.linux.system import System


class Module(Post, System):
    __info__ = {
        "name": "Linux Service Controller",
        "description": "Manage Linux services (status, start, stop, restart, enable, disable)",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
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
            output = self.cmd_exec("{cmd} 2>&1".format(cmd=command))
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
