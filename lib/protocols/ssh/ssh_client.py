from core.framework.base_module import BaseModule
from core.framework.option import OptString, OptPort
from core.output_handler import print_success, print_status, print_error, print_info, print_warning
import time
import socket
import paramiko


class SSHSocket:
    """
    SSH helper:
      - connect via password OR private key (RSA/ECDSA/ED25519/DSA)
      - exec(command) -> (stdout_bytes, stderr_bytes, exit_code)
      - interactive shell: open_shell(), send(), recv(), recv_until(), recv_all()
    """

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        password: str | None = None,
        key_file: str | None = None,
        passphrase: str | None = None,
        timeout: int = 10,
        allow_agent: bool = False,
        look_for_keys: bool = False,
        auto_add_hostkey: bool = True,
    ):
        self.host = host
        self.port = port
        self.username = username

        self.password = password
        self.key_file = key_file
        self.passphrase = passphrase

        self.timeout = timeout
        self.allow_agent = allow_agent
        self.look_for_keys = look_for_keys

        self.client = paramiko.SSHClient()
        if auto_add_hostkey:
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            self.client.set_missing_host_key_policy(paramiko.RejectPolicy())

        self.connected = False
        self.shell = None  # type: paramiko.Channel | None

        self._connect()
        print_success(f"SSH connection established to {self.host}:{self.port} as {self.username}")

    # ---------- Connection helpers ----------

    @staticmethod
    def _load_private_key(path: str, passphrase: str | None):
        """
        Try to load a private key file with multiple key types.
        """
        loaders = [
            paramiko.RSAKey.from_private_key_file,
            paramiko.ECDSAKey.from_private_key_file,
            paramiko.Ed25519Key.from_private_key_file,
            paramiko.DSSKey.from_private_key_file,  # DSA (legacy)
        ]
        last_err = None
        for loader in loaders:
            try:
                return loader(path, password=passphrase)
            except Exception as e:
                last_err = e
        raise ValueError(f"Unable to load private key '{path}': {last_err}")

    def _connect(self):
        try:
            kwargs = dict(
                hostname=self.host,
                port=self.port,
                username=self.username,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                allow_agent=self.allow_agent,
                look_for_keys=self.look_for_keys,
            )

            if self.key_file:
                # Robust: explicitly load key (supports RSA/ECDSA/ED25519/DSA)
                pkey = self._load_private_key(self.key_file, self.passphrase)
                kwargs["pkey"] = pkey
            else:
                kwargs["password"] = self.password

            self.client.connect(**kwargs)
            self.connected = True

        except Exception as e:
            self.connected = False
            print_error(f"Failed to connect via SSH to {self.host}:{self.port} -> {e}")
            raise

    # ---------- Exec mode ----------

    def exec(self, command: str, get_pty: bool = False, timeout: int | None = None):
        """
        Execute a command (non-interactive).
        Returns: (stdout_bytes, stderr_bytes, exit_code)
        """
        if not self.connected:
            raise ConnectionError("SSH client is not connected")

        try:
            print_info(f"Executing: {command}")
            stdin, stdout, stderr = self.client.exec_command(
                command,
                get_pty=get_pty,
                timeout=timeout
            )

            out_b = stdout.read()
            err_b = stderr.read()
            exit_code = stdout.channel.recv_exit_status()
            return out_b, err_b, exit_code

        except Exception as e:
            print_error(f"SSH exec failed -> {e}")
            raise

    def exec_text(self, command: str, encoding: str = "utf-8", errors: str = "replace"):
        """
        Convenience wrapper: returns (stdout_text, stderr_text, exit_code)
        """
        out_b, err_b, code = self.exec(command)
        return out_b.decode(encoding, errors), err_b.decode(encoding, errors), code

    # ---------- Interactive shell mode ----------

    def open_shell(self, term: str = "xterm", width: int = 120, height: int = 40):
        """
        Open an interactive shell channel.
        """
        if not self.connected:
            raise ConnectionError("SSH client is not connected")

        try:
            self.shell = self.client.invoke_shell(term=term, width=width, height=height)
            self.shell.settimeout(self.timeout)
            print_status("Interactive shell opened")
            return self.shell
        except Exception as e:
            print_error(f"Failed to open interactive shell -> {e}")
            raise

    def send(self, data: bytes | str):
        """
        Send to interactive shell.
        """
        if self.shell is None:
            raise RuntimeError("Shell not opened. Call open_shell() first.")

        try:
            if isinstance(data, str):
                data = data.encode("utf-8")

            self.shell.sendall(data)
            print_info(f"Sent {len(data)} bytes to shell")
        except Exception as e:
            print_error(f"Shell send failed -> {e}")
            raise

    def recv(self, size: int = 4096) -> bytes:
        """
        Receive up to `size` bytes from interactive shell (single read).
        """
        if self.shell is None:
            raise RuntimeError("Shell not opened. Call open_shell() first.")

        try:
            data = self.shell.recv(size)
            return data
        except socket.timeout:
            return b""
        except Exception as e:
            print_error(f"Shell recv failed -> {e}")
            raise

    def recv_until(
        self,
        delimiter: bytes,
        chunk_size: int = 4096,
        max_bytes: int = 2_000_000,
    ) -> bytes:
        """
        Receive until delimiter appears (or timeout).
        """
        if self.shell is None:
            raise RuntimeError("Shell not opened. Call open_shell() first.")

        if not isinstance(delimiter, (bytes, bytearray)) or len(delimiter) == 0:
            raise ValueError("delimiter must be non-empty bytes")

        data = b""
        try:
            while delimiter not in data:
                chunk = self.recv(chunk_size)
                if not chunk:
                    # timeout / no data
                    break
                data += chunk
                if len(data) >= max_bytes:
                    print_warning("recv_until reached max_bytes limit")
                    break
            return data
        except Exception as e:
            print_error(f"recv_until failed -> {e}")
            raise

    def recv_all(
        self,
        idle_timeout: float = 0.6,
        chunk_size: int = 4096,
        max_bytes: int = 5_000_000,
    ) -> bytes:
        """
        Read everything currently available until no new data arrives for `idle_timeout`.
        Great for prompts/banners.
        """
        if self.shell is None:
            raise RuntimeError("Shell not opened. Call open_shell() first.")

        data = b""
        last = time.time()

        while True:
            chunk = self.recv(chunk_size)
            if chunk:
                data += chunk
                last = time.time()
                if len(data) >= max_bytes:
                    print_warning("recv_all reached max_bytes limit")
                    break
            else:
                if (time.time() - last) >= idle_timeout:
                    break

        return data

    # ---------- Close ----------

    def close(self):
        """
        Close shell + SSH session.
        """
        try:
            if self.shell is not None:
                try:
                    self.shell.close()
                except Exception:
                    pass
                self.shell = None

            self.client.close()
            self.connected = False
            print_status(f"SSH connection closed ({self.host}:{self.port})")
        except Exception as e:
            print_warning(f"Close failed -> {e}")


class Ssh_client(BaseModule):
    ssh_host = OptString("", "Target IP or hostname", True)
    ssh_port = OptPort(22, "Target SSH port", True)

    ssh_user = OptString("root", "SSH username", True)
    ssh_pass = OptString("", "SSH password (optional if key is used)", False)

    ssh_key = OptString("", "SSH private key file path (RSA/ECDSA/ED25519/DSA)", False)
    ssh_passphrase = OptString("", "Private key passphrase (if encrypted)", False)

    def __init__(self, framework=None):
        super().__init__(framework)

    def open_ssh_connection(
        self,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        key_file: str | None = None,
        passphrase: str | None = None,
        timeout: int = 10,
        allow_agent: bool = False,
        look_for_keys: bool = False,
    ) -> SSHSocket:
        ssh_host = host if host else self.ssh_host.value
        ssh_port = port if port else self.ssh_port.value
        ssh_user = username if username else self.ssh_user.value

        ssh_key = key_file if key_file else (self.ssh_key.value or None)
        ssh_passphrase = passphrase if passphrase else (self.ssh_passphrase.value or None)

        # If key is not used, fall back to password
        ssh_password = password if password is not None else (self.ssh_pass.value or None)

        if not ssh_key and not ssh_password:
            raise ValueError("Missing authentication: provide either password or key_file")

        return SSHSocket(
            host=ssh_host,
            port=ssh_port,
            username=ssh_user,
            password=ssh_password,
            key_file=ssh_key,
            passphrase=ssh_passphrase,
            timeout=timeout,
            allow_agent=allow_agent,
            look_for_keys=look_for_keys,
        )
