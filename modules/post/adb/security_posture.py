from kittysploit import *


class Module(Post):

    __info__ = {
        "name": "Android Security Posture",
        "description": "Assess Android security posture (debug, root, encryption, boot integrity, network exposure)",
        "author": "KittySploit Team",
        "session_type": SessionType.ANDROID,
    }

    verbose = OptBool(False, "Show additional diagnostic values", False)

    def run(self):
        try:
            print_status("Running Android security posture checks...")
            print_info("=" * 80)

            self._check_debug_state()
            self._check_root_state()
            self._check_selinux()
            self._check_crypto_state()
            self._check_boot_integrity()
            self._check_dev_settings()
            self._check_network_exposure()

            print_info("=" * 80)
            print_success("Android security posture audit completed")
            return True
        except Exception as e:
            print_error(f"Error: {e}")
            return False

    def _cmd(self, command):
        return (self.cmd_execute(command) or "").strip()

    def _prop(self, name):
        return self._cmd(f"getprop {name}")

    def _check_debug_state(self):
        print_status("Check: Build and debug state")
        debuggable = self._prop("ro.debuggable")
        secure = self._prop("ro.secure")
        build_tags = self._prop("ro.build.tags")

        if debuggable == "1":
            print_warning("ro.debuggable=1 (debug build behavior enabled)")
        elif debuggable:
            print_success(f"ro.debuggable={debuggable}")
        else:
            print_warning("Could not read ro.debuggable")

        if secure == "0":
            print_error("ro.secure=0 (insecure build setting)")
        elif secure:
            print_success(f"ro.secure={secure}")
        else:
            print_warning("Could not read ro.secure")

        if "test-keys" in build_tags:
            print_warning(f"Build tags include test-keys ({build_tags})")
        elif build_tags:
            print_success(f"Build tags: {build_tags}")

        print_info("-" * 80)

    def _check_root_state(self):
        print_status("Check: Root exposure")
        uid_line = self._cmd("id")
        su_path = self._cmd("which su")
        su_exec = self._cmd("su -c id")

        if "uid=0" in uid_line:
            print_error("Current shell already runs as root (uid=0)")
        else:
            print_success(f"Shell identity: {uid_line or 'unknown'}")

        if su_path and "not found" not in su_path.lower():
            print_warning(f"'su' binary found: {su_path}")
        else:
            print_success("'su' binary not found in PATH")

        if su_exec and "uid=0" in su_exec:
            print_warning("su escalation appears possible (su -c id returned uid=0)")
        elif self.verbose and su_exec:
            print_info(f"su -c id output: {su_exec}")

        print_info("-" * 80)

    def _check_selinux(self):
        print_status("Check: SELinux mode")
        mode = self._cmd("getenforce")
        if mode.lower() == "enforcing":
            print_success("SELinux is Enforcing")
        elif mode:
            print_warning(f"SELinux mode: {mode}")
        else:
            print_warning("Could not determine SELinux mode")
        print_info("-" * 80)

    def _check_crypto_state(self):
        print_status("Check: Encryption state")
        crypto_state = self._prop("ro.crypto.state")
        crypto_type = self._prop("ro.crypto.type")

        if crypto_state.lower() == "encrypted":
            print_success("Device encryption is enabled")
        elif crypto_state:
            print_warning(f"Encryption state: {crypto_state}")
        else:
            print_warning("Could not read encryption state")

        if crypto_type:
            print_info(f"Encryption type: {crypto_type}")
        print_info("-" * 80)

    def _check_boot_integrity(self):
        print_status("Check: Verified boot and lock state")
        vb_state = self._prop("ro.boot.verifiedbootstate")
        flash_locked = self._prop("ro.boot.flash.locked")

        if vb_state:
            if vb_state.lower() in ("green", "locked"):
                print_success(f"Verified boot state: {vb_state}")
            else:
                print_warning(f"Verified boot state: {vb_state}")
        else:
            print_warning("Could not read verified boot state")

        if flash_locked == "1":
            print_success("Bootloader appears locked (ro.boot.flash.locked=1)")
        elif flash_locked:
            print_warning(f"Bootloader lock state: {flash_locked}")
        else:
            print_warning("Could not read bootloader lock state")
        print_info("-" * 80)

    def _check_dev_settings(self):
        print_status("Check: Developer and install settings")
        adb_enabled = self._cmd("settings get global adb_enabled")
        dev_enabled = self._cmd("settings get global development_settings_enabled")
        unknown_src_secure = self._cmd("settings get secure install_non_market_apps")
        unknown_src_global = self._cmd("settings get global install_non_market_apps")

        if adb_enabled == "1":
            print_warning("USB debugging is enabled (adb_enabled=1)")
        elif adb_enabled:
            print_success(f"adb_enabled={adb_enabled}")
        else:
            print_warning("Could not read adb_enabled")

        if dev_enabled == "1":
            print_warning("Developer options are enabled")
        elif dev_enabled:
            print_success(f"development_settings_enabled={dev_enabled}")

        unknown_src = unknown_src_secure if unknown_src_secure and unknown_src_secure != "null" else unknown_src_global
        if unknown_src == "1":
            print_warning("Unknown sources install appears enabled")
        elif unknown_src:
            print_success(f"install_non_market_apps={unknown_src}")

        if self.verbose:
            verifier = self._cmd("settings get global verifier_verify_adb_installs")
            if verifier:
                print_info(f"verifier_verify_adb_installs={verifier}")
        print_info("-" * 80)

    def _check_network_exposure(self):
        print_status("Check: Network exposure")
        ip_info = self._cmd("ip addr")
        if not ip_info:
            print_warning("Could not read interface configuration")
            return

        has_public = False
        for line in ip_info.splitlines():
            line = line.strip()
            if line.startswith("inet ") and not line.startswith("inet 127."):
                print_info(f"  {line}")
                if not line.startswith("inet 10.") and not line.startswith("inet 172.16") and not line.startswith("inet 172.17") and not line.startswith("inet 172.18") and not line.startswith("inet 172.19") and not line.startswith("inet 172.2") and not line.startswith("inet 192.168."):
                    has_public = True

        if has_public:
            print_warning("At least one non-RFC1918 IPv4 address detected")
        else:
            print_success("No obvious public IPv4 address detected")
