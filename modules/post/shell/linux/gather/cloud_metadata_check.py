from kittysploit import *
from lib.post.linux.system import System


class Module(Post, System):
    __info__ = {
        "name": "Linux Cloud Metadata Check",
        "description": "Check if cloud instance metadata endpoints are reachable from target host",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
    }

    timeout = OptInteger(2, "HTTP timeout in seconds", False)

    def _run_cmd(self, command: str) -> str:
        try:
            output = self.cmd_exec(command)
            return output.strip() if output else ""
        except Exception:
            return ""

    def _print_section(self, title: str):
        print_status("=" * 60)
        print_status(title)
        print_status("=" * 60)

    def _check_endpoint(self, name: str, command: str) -> bool:
        output = self._run_cmd(command)
        if output:
            print_warning(f"{name}: reachable")
            print_info(f"  {output}")
            return True
        print_info(f"{name}: not reachable")
        return False

    def run(self):
        self._print_section("Cloud Metadata Reachability")
        timeout = int(self.timeout)

        if self.command_exists("curl"):
            client = "curl -sS -m {t}".format(t=timeout)
        elif self.command_exists("wget"):
            client = "wget -q -T {t} -O -".format(t=timeout)
        else:
            print_error("Neither curl nor wget is available on target")
            return False

        findings = 0

        # AWS IMDSv1 quick check
        findings += int(
            self._check_endpoint(
                "AWS IMDSv1",
                "{c} http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null | head -n 1".format(c=client),
            )
        )

        # AWS IMDSv2 check (token + request)
        token = self._run_cmd(
            "curl -sS -m {t} -X PUT http://169.254.169.254/latest/api/token "
            "-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' 2>/dev/null".format(t=timeout)
        )
        if token:
            output = self._run_cmd(
                "curl -sS -m {t} -H 'X-aws-ec2-metadata-token: {tok}' "
                "http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null | head -n 1".format(
                    t=timeout, tok=token.replace("'", "")
                )
            )
            if output:
                print_warning("AWS IMDSv2: reachable")
                print_info(f"  {output}")
                findings += 1
            else:
                print_info("AWS IMDSv2: token acquired but metadata query failed")
        else:
            print_info("AWS IMDSv2: not reachable or token endpoint blocked")

        findings += int(
            self._check_endpoint(
                "Azure IMDS",
                "{c} -H 'Metadata:true' "
                "'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null | head -c 180".format(
                    c=client
                ),
            )
        )
        findings += int(
            self._check_endpoint(
                "GCP Metadata",
                "{c} -H 'Metadata-Flavor: Google' "
                "http://metadata.google.internal/computeMetadata/v1/instance/id 2>/dev/null | head -n 1".format(c=client),
            )
        )
        findings += int(
            self._check_endpoint(
                "OpenStack Metadata",
                "{c} http://169.254.169.254/openstack/latest/meta_data.json 2>/dev/null | head -c 180".format(c=client),
            )
        )

        self._print_section("Summary")
        if findings > 0:
            print_warning(f"Detected {findings} reachable metadata endpoint(s)")
        else:
            print_success("No known cloud metadata endpoint was reachable")
        return True
