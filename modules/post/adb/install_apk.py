from kittysploit import *
import os

class Module(Post):
    __info__ = {
        'name': 'Android Install APK',
        'description': 'Install an APK on an Android device',
        'author': 'KittySploit Team',
        'session_type': SessionType.ANDROID,
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