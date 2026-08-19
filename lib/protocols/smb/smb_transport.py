"""SMB transport helpers shared across relay and SAMR clients."""

from lib.protocols.samr.smb_transport import PYSMB_AVAILABLE, SmbPipeTransport

__all__ = ["PYSMB_AVAILABLE", "SmbPipeTransport"]
