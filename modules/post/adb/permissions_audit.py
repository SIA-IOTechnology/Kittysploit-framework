from kittysploit import *
import re


class Module(Post):

    __info__ = {
        "name": "Android Permissions Audit",
        "description": "Audit installed apps for sensitive Android permissions and risky flags",
        "author": "KittySploit Team",
        "session_type": SessionType.ANDROID,
    }

    third_party_only = OptBool(True, "Audit only third-party apps (pm list packages -3)", False)
    verbose = OptBool(False, "Show extra package diagnostics", False)

    SENSITIVE_PERMISSIONS = [
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.QUERY_ALL_PACKAGES",
    ]

    def run(self):
        try:
            print_status("Running Android permissions audit...")
            pkg_list = self._get_packages()
            if not pkg_list:
                print_error("No package found (or ADB output unavailable)")
                return False

            print_info(f"Packages in scope: {len(pkg_list)}")
            print_info("=" * 80)

            findings = 0
            processed = 0
            max_to_process = 80

            for pkg in pkg_list[:max_to_process]:
                processed += 1
                package_dump = self._cmd(f"dumpsys package {pkg}")
                if not package_dump:
                    continue

                matched = self._extract_sensitive_permissions(package_dump)
                if not matched:
                    continue

                findings += 1
                flags = self._extract_flags(package_dump)
                print_warning(f"{pkg}")
                print_info(f"  Sensitive permissions: {', '.join(matched)}")
                if flags:
                    print_info(f"  Risky flags: {', '.join(flags)}")
                if self.verbose:
                    uid_line = self._extract_uid_line(package_dump)
                    if uid_line:
                        print_info(f"  {uid_line}")

            print_info("-" * 80)
            if len(pkg_list) > max_to_process:
                print_warning(
                    f"Scanned first {max_to_process}/{len(pkg_list)} packages to keep runtime reasonable"
                )
            else:
                print_success(f"Scanned {processed} package(s)")

            if findings == 0:
                print_success("No high-signal sensitive permission set detected in scanned apps")
            else:
                print_warning(f"Found {findings} app(s) with sensitive permission footprint")
            return True
        except Exception as e:
            print_error(f"Error: {e}")
            return False

    def _cmd(self, command):
        return (self.cmd_execute(command) or "").strip()

    def _get_packages(self):
        cmd = "pm list packages -3" if self.third_party_only else "pm list packages"
        out = self._cmd(cmd)
        if not out or "not connected" in out.lower():
            return []
        packages = re.findall(r"(?mi)^\s*package:([^\s]+)\s*$", out)
        return sorted(set(p.strip() for p in packages if p.strip()))

    def _extract_sensitive_permissions(self, dump_text):
        matched = []
        for perm in self.SENSITIVE_PERMISSIONS:
            if perm not in dump_text:
                continue

            # Prefer permissions that appear with granted=true in dumpsys output.
            granted_pattern = re.compile(
                rf"{re.escape(perm)}.*granted=true",
                flags=re.IGNORECASE
            )
            if granted_pattern.search(dump_text):
                matched.append(f"{perm.split('.')[-1]}(granted)")
            else:
                matched.append(perm.split(".")[-1])
        return matched

    def _extract_flags(self, dump_text):
        risky = []
        lower = dump_text.lower()

        if "debuggable" in lower:
            risky.append("debuggable")
        if "testonly=true" in lower or "testonly" in lower:
            risky.append("testOnly")
        if "allowbackup=true" in lower:
            risky.append("allowBackup=true")
        if "usescleartexttraffic=true" in lower:
            risky.append("usesCleartextTraffic=true")

        return sorted(set(risky))

    def _extract_uid_line(self, dump_text):
        for line in dump_text.splitlines():
            text = line.strip()
            if text.startswith("userId=") or "uid=" in text:
                return f"UID info: {text}"
        return None
