from kittysploit import *
import ipaddress
import re


class Module(Post):
    __info__ = {
        "name": "Pivot Autoroute",
        "description": "Discover reachable internal subnets from the active session and add framework pivot routes",
        "platform": Platform.MULTI,
        "author": "KittySploit Team",
        "session_type": [
            SessionType.SHELL,
            SessionType.METERPRETER,
            SessionType.SSH,
            SessionType.WINRM,
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation', 'network_probe'],
        'expected_requests': 3,
        'reversible': True,
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

    target = OptChoice("auto", "Target platform: auto, unix, windows", False, choices=["auto", "unix", "windows"])
    proxy_port = OptInteger(1080, "Local SOCKS proxy port for routed subnets", False)
    extra_subnets = OptString("", "Comma-separated extra CIDRs to route", False)
    install_wrapper = OptBool(True, "Install socket wrapper after adding routes", False)
    dry_run = OptBool(False, "Only print discovered subnets without modifying routes", False)

    IPV4_CIDR = re.compile(r"\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})/(\d{1,2})\b")
    IPV4 = re.compile(r"\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b")

    def _cmd(self, command: str) -> str:
        try:
            output = self.cmd_execute(command)
            return output.strip() if output else ""
        except Exception:
            return ""

    def _session_id_value(self) -> str:
        value = getattr(self, "session_id", "")
        if hasattr(value, "value"):
            return str(value.value or "").strip()
        return str(value or "").strip()

    def _detect_platform(self) -> str:
        selected = str(self.target or "auto").strip().lower()
        if selected in ("unix", "windows"):
            return selected
        if self._cmd("uname -s 2>/dev/null"):
            return "unix"
        if "windows" in self._cmd("cmd /c ver").lower():
            return "windows"
        return "unix"

    def _discover_unix_subnets(self) -> list:
        subnets = []
        output = self._cmd("ip -4 route show scope link 2>/dev/null; ip -4 route 2>/dev/null")
        for match in self.IPV4_CIDR.finditer(output or ""):
            subnets.append(f"{match.group(1)}/{match.group(2)}")
        addr_out = self._cmd("ip -4 addr show scope global 2>/dev/null")
        for line in (addr_out or "").splitlines():
            cidr_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if not cidr_match:
                continue
            ip = cidr_match.group(1)
            prefix = int(cidr_match.group(2))
            if ip.startswith("127."):
                continue
            try:
                network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
                subnets.append(str(network))
            except ValueError:
                pass
        return subnets

    def _discover_windows_subnets(self) -> list:
        subnets = []
        output = self._cmd("route print -4")
        for line in (output or "").splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            dest, mask = parts[0], parts[2]
            if dest in ("0.0.0.0", "Network Destination"):
                continue
            if dest.startswith("127."):
                continue
            try:
                network = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
                if network.prefixlen >= 8:
                    subnets.append(str(network))
            except ValueError:
                pass
        return subnets

    def _normalize_subnets(self, raw_subnets: list) -> list:
        seen = set()
        normalized = []
        for item in raw_subnets:
            item = str(item or "").strip()
            if not item:
                continue
            if "/" not in item:
                item += "/32"
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError:
                continue
            if net.is_loopback or net.is_link_local:
                continue
            key = str(net)
            if key in seen:
                continue
            seen.add(key)
            normalized.append(key)
        return sorted(normalized, key=lambda s: ipaddress.ip_network(s).prefixlen, reverse=True)

    def run(self):
        session_id = self._session_id_value()
        if not session_id:
            raise ProcedureError(FailureType.ConfigurationError, "session_id is required")

        if not self.framework or not hasattr(self.framework, "route_manager"):
            raise ProcedureError(FailureType.ConfigurationError, "Route manager not available")

        platform = self._detect_platform()
        print_info("=" * 80)
        print_status(f"Autoroute discovery ({platform}) for session {session_id}")

        discovered = self._discover_windows_subnets() if platform == "windows" else self._discover_unix_subnets()
        extras = [part.strip() for part in str(self.extra_subnets or "").split(",") if part.strip()]
        subnets = self._normalize_subnets(discovered + extras)

        if not subnets:
            print_warning("No routable subnets discovered")
            return False

        print_info("Discovered subnets:")
        for subnet in subnets:
            print_info(f"  {subnet}")

        if self.dry_run:
            print_warning("Dry run enabled — routes not modified")
            return True

        added = 0
        proxy_port = int(self.proxy_port or 1080)
        for subnet in subnets:
            if self.framework.route_manager.add_route(
                subnet_str=subnet,
                session_id=session_id,
                proxy_host="127.0.0.1",
                proxy_port=proxy_port,
            ):
                added += 1

        if added and self.install_wrapper:
            try:
                from lib.pivot.socket_wrapper import install_socket_wrapper
                install_socket_wrapper(self.framework)
                print_success("Socket wrapper installed")
            except Exception as exc:
                print_warning(f"Could not install socket wrapper: {exc}")

        print_info("-" * 80)
        print_success(f"Added {added} route(s)")
        print_info("Ensure a SOCKS proxy is listening locally (e.g. post/shell/linux/pivot/socks_proxy)")
        print_info("=" * 80)
        return added > 0
