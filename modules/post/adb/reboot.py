from kittysploit import *

class Module(Post):

    __info__ = {
        'name': 'Android Reboot',
        'description': 'Reboot an Android device',
        'author': 'KittySploit Team',
        'session_type': SessionType.ANDROID,
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