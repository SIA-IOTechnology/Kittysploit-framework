from kittysploit import *
import re

class Module(Post):

    __info__ = {
        'name': 'Android Battery Level',
        'description': 'Get the battery level of an Android device',
        'author': 'KittySploit Team',
        'session_type': SessionType.ANDROID,
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