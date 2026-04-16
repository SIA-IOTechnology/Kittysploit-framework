from core.framework.base_module import BaseModule
from core.framework.option import OptString
from core.framework.failure import fail, ErrorDescription
from core.output_handler import print_success


class Http_login(BaseModule):

    username = OptString("admin", "A specific username to authenticate as", True)
    password = OptString("admin", "A specific password to authenticate with", True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        setattr(fail, "LoginFailed", ErrorDescription("Login failed"))

    def login_success(self):
        """Backward-compatible helper used by legacy HTTP modules."""
        print_success("Login successful")
        return True

    def login_failed(self, raise_exception: bool = False):
        """Backward-compatible helper used by legacy HTTP modules."""
        return fail.LoginFailed(raise_exception=raise_exception)
