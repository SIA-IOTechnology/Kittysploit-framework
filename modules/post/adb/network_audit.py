from kittysploit import *
import re


class Module(Post):

    __info__ = {
        "name": "Android Network Audit",
        "description": "Audit Android network posture: interfaces, IPs, routes, DNS, Wi-Fi, proxy, VPN",
        "author": "KittySploit Team",
        "session_type": SessionType.ANDROID,
    }

    verbose = OptBool(False, "Show additional network diagnostics", False)

    def run(self):
        try:
            print_status("Running Android network audit...")
            print_info("=" * 80)

            self._check_interfaces()
            self._check_routes()
            self._check_dns()
            self._check_wifi_state()
            self._check_proxy()
            self._check_vpn()

            print_info("=" * 80)
            print_success("Android network audit completed")
            return True
        except Exception as e:
            print_error(f"Error: {e}")
            return False

    def _cmd(self, command):
        return (self.cmd_execute(command) or "").strip()

    def _check_interfaces(self):
        print_status("Check: Interfaces and IP addresses")
        out = self._cmd("ip addr")
        if not out:
            print_warning("Could not read network interfaces via ip addr")
            print_info("-" * 80)
            return

        active_iface = None
        found_addr = 0
        for line in out.splitlines():
            text = line.strip()
            m = re.match(r"^\d+:\s+([^:]+):", text)
            if m:
                active_iface = m.group(1)
                continue

            if text.startswith("inet "):
                found_addr += 1
                print_info(f"  {active_iface}: {text}")
            elif self.verbose and text.startswith("inet6 "):
                print_info(f"  {active_iface}: {text}")

        if found_addr == 0:
            print_warning("No IPv4 address detected in ip addr output")
        else:
            print_success(f"Detected {found_addr} IPv4 address entry(ies)")
        print_info("-" * 80)

    def _check_routes(self):
        print_status("Check: Routing table")
        out = self._cmd("ip route")
        if not out:
            print_warning("Could not read routing table")
            print_info("-" * 80)
            return

        default_routes = []
        for line in out.splitlines():
            text = line.strip()
            if text.startswith("default "):
                default_routes.append(text)
            if self.verbose:
                print_info(f"  {text}")

        if default_routes:
            print_success("Default route(s):")
            for route in default_routes:
                print_info(f"  {route}")
        else:
            print_warning("No default route detected")
        print_info("-" * 80)

    def _check_dns(self):
        print_status("Check: DNS configuration")

        props = [
            "net.dns1",
            "net.dns2",
            "net.dns3",
            "net.dns4",
            "dhcp.wlan0.dns1",
            "dhcp.wlan0.dns2",
            "dhcp.rmnet_data0.dns1",
            "dhcp.rmnet_data0.dns2",
        ]

        values = []
        for prop in props:
            v = self._cmd(f"getprop {prop}")
            if v:
                values.append((prop, v))

        if values:
            seen = set()
            for prop, val in values:
                key = (prop, val)
                if key in seen:
                    continue
                seen.add(key)
                print_info(f"  {prop}={val}")
            print_success(f"Found {len(seen)} DNS-related property values")
        else:
            print_warning("No DNS property found via getprop")

        if self.verbose:
            resolv = self._cmd("cat /etc/resolv.conf")
            if resolv:
                print_info("  /etc/resolv.conf:")
                for line in resolv.splitlines()[:20]:
                    if line.strip():
                        print_info(f"    {line.strip()}")
        print_info("-" * 80)

    def _check_wifi_state(self):
        print_status("Check: Wi-Fi state")
        status = self._cmd("cmd wifi status")
        if not status:
            status = self._cmd("dumpsys wifi | head -80")

        if not status:
            print_warning("Could not retrieve Wi-Fi state")
            print_info("-" * 80)
            return

        low = status.lower()
        if "enabled" in low and "disabled" not in low:
            print_success("Wi-Fi appears enabled")
        elif "disabled" in low:
            print_info("Wi-Fi appears disabled")

        # SSID can be masked or unavailable depending on Android version/permission.
        ssid_match = re.search(r"ssid[:=]\s*([^\n,]+)", status, flags=re.IGNORECASE)
        if ssid_match:
            print_info(f"  SSID: {ssid_match.group(1).strip()}")

        if self.verbose:
            for line in status.splitlines()[:80]:
                text = line.strip()
                if text:
                    print_info(f"  {text}")
        print_info("-" * 80)

    def _check_proxy(self):
        print_status("Check: Proxy settings")
        http_proxy = self._cmd("settings get global http_proxy")
        global_proxy_host = self._cmd("settings get global global_http_proxy_host")
        global_proxy_port = self._cmd("settings get global global_http_proxy_port")

        found = False
        if http_proxy and http_proxy.lower() not in ("null", ":0"):
            found = True
            print_warning(f"http_proxy={http_proxy}")

        if global_proxy_host and global_proxy_host.lower() != "null":
            found = True
            port = global_proxy_port if global_proxy_port and global_proxy_port.lower() != "null" else "?"
            print_warning(f"global_http_proxy={global_proxy_host}:{port}")

        if not found:
            print_success("No explicit global proxy detected")
        print_info("-" * 80)

    def _check_vpn(self):
        print_status("Check: VPN indicators")
        out = self._cmd("ip addr")
        if not out:
            print_warning("Could not check VPN interfaces")
            return

        vpn_ifaces = []
        for line in out.splitlines():
            m = re.match(r"^\d+:\s+([^:]+):", line.strip())
            if not m:
                continue
            iface = m.group(1)
            if iface.startswith("tun") or iface.startswith("ppp") or iface.startswith("wg"):
                vpn_ifaces.append(iface)

        if vpn_ifaces:
            print_warning(f"Possible VPN interface(s) detected: {', '.join(sorted(set(vpn_ifaces)))}")
        else:
            print_success("No obvious VPN interface detected")

        if self.verbose:
            vpn_dump = self._cmd("dumpsys connectivity | grep -i vpn")
            if vpn_dump:
                print_info("  Connectivity VPN hints:")
                for line in vpn_dump.splitlines()[:20]:
                    if line.strip():
                        print_info(f"    {line.strip()}")
