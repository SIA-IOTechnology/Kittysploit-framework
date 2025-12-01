from paramiko import SSHClient, AutoAddPolicy
from core.framework.base_module import BaseModule
from core.output_handler import print_success, print_status, print_error, print_info, print_warning
from core.framework.option.option_string import OptString
from core.framework.option.option_port import OptPort
from core.framework.option.option_bool import OptBool

class SSHClient(BaseModule):
    """SSH client module"""
    
    target = OptString("", "Target IP or hostname", True)
    port = OptPort(22, "Target port", True)
    ssh_user = OptString("", "SSH username", True)
    ssh_password = OptString("", "SSH password", True)
    ssh_key = OptString("", "SSH private key", False)
    ssh_timeout = OptPort(10, "SSH timeout in seconds", True)
    ssh_verify = OptBool(True, "Verify SSH host key: true/false", True)
    ssh_proxy = OptString("", "Proxy URL (e.g., 'http://127.0.0.1:8080')", False)


