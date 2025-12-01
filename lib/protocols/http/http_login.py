from core.framework.base_module import BaseModule
from core.framework.option import OptString
from core.framework.failure import fail, ErrorDescription


class Http_login(BaseModule):

    username = OptString("admin", "A specific username to authenticate as", True)
    password = OptString("admin", "A specific password to authenticate with", True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        setattr(fail, "LoginFailed", ErrorDescription("Login failed"))
