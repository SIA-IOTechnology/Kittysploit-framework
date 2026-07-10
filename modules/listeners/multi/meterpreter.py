#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Compatibility alias for the Meterpreter reverse TCP listener."""

from kittysploit import Listener
from modules.listeners.multi.meterpreter_reverse_tcp import Module as _MeterpreterReverseTcp


class Module(Listener, _MeterpreterReverseTcp):
    """Alias for listeners/multi/meterpreter_reverse_tcp."""

    __info__ = {
        "name": "Meterpreter Reverse TCP (compat alias)",
        "description": (
            "Compatibility alias for listeners/multi/meterpreter_reverse_tcp. "
            "Prefer meterpreter_reverse_tcp for new configurations."
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
    }
