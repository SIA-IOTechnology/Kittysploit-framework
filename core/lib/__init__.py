# Import here to avoid circular imports
def get_remote_connection():
    from core.lib.remote_connection import RemoteConnection
    return RemoteConnection

def get_connection_manager():
    from core.lib.connection_manager import ConnectionManager
    return ConnectionManager

def get_tunnel_proxy_manager():
    from core.lib.tunnel_proxy import TunnelProxyManager
    return TunnelProxyManager

def remote(host: str, port: int, protocol: str = 'tcp', **kwargs):
    """
    Create a remote connection to a target host
    
    Args:
        host: Target hostname or IP address
        port: Target port number
        protocol: Connection protocol ('tcp', 'ssh', 'http', 'https', 'rpc', 'api')
        **kwargs: Additional connection parameters (username, password, api_key, timeout)
    """
    RemoteConnection = get_remote_connection()
    return RemoteConnection(host, port, protocol, **kwargs)

def get_current_remote():
    """
    Get the current active remote connection
    """
    ConnectionManager = get_connection_manager()
    return ConnectionManager.get_current_remote()

def send_command(command: str):
    """
    Send a command to the current remote connection
    """
    RemoteConnection = get_remote_connection()
    return RemoteConnection.send_command(command)

def disassemble(data: bytes, start_address: int = 0):
    """
    Disassemble data
    """
    from core.lib.disassembler import x86Disassembler
    return x86Disassembler.disassemble(data, start_address)

def analyze_elf(path: str):
    """
    Analyze an ELF file
    """
    from core.lib.elf_analyzer import ELFAnalyzer
    analyzer = ELFAnalyzer(path)
    return analyzer.get_binary_info()

def analyze_pe(path: str):
    """
    Analyze a PE file
    """
    from core.lib.pe_analyzer import PEAnalyzer
    return PEAnalyzer.analyze(path)

__all__ = ['get_remote_connection', 
            'get_connection_manager', 
            'get_tunnel_proxy_manager',
            'remote',
            'get_current_remote',
            'send_command',
            'disassemble',
            'analyze_elf',
            'analyze_pe']
