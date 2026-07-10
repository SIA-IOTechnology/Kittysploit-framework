class ProtocolClient:
    PLUGIN_NAME = "PROTOCOL"

    def __init__(self, serverConfig, target, targetPort, extendedSecurity=True):
        self.serverConfig = serverConfig
        self.targetHost = target.hostname
        self.targetPort = target.port if target.port is not None else targetPort
        self.target = target
        self.extendedSecurity = extendedSecurity
        self.session = None
        self.sessionData = {}

    def initConnection(self, authdata, kdc=None):
        raise RuntimeError("Virtual Function")

    def killConnection(self):
        raise RuntimeError("Virtual Function")

    def keepAlive(self):
        raise RuntimeError("Virtual Function")
