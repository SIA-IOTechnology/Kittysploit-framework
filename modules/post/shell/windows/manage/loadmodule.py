#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Alias module: ``loadmodule`` → same as run_assembly."""

from kittysploit import *
from modules.post.shell.windows.manage.run_assembly import Module as RunAssemblyModule


class Module(RunAssemblyModule):
    __info__ = {
        "name": "Windows loadmodule (alias)",
        "description": (
            "Alias of post/shell/windows/manage/run_assembly — "
            "set module=<catalog|path> then run."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL, SessionType.POLLING],
        "references": [
            "https://attack.mitre.org/techniques/T1620/",
        ],
    }
