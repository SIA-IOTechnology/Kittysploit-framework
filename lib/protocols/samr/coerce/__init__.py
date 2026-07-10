# -*- coding: utf-8 -*-
"""DCE/RPC coercion primitives over SMB named pipes (pysmb, no impacket)."""

from lib.protocols.samr.coerce.dfscoerce import dfscoerce_coerce
from lib.protocols.samr.coerce.petitpotam import petitpotam_coerce

__all__ = ["dfscoerce_coerce", "petitpotam_coerce"]
