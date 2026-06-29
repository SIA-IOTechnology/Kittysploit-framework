#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Entry point when running: python -m kittysploit  or  kittysploit (pip-installed script).
"""

from lib.analysis.malware.dotnet_runtime import configure_pythonnet_env

configure_pythonnet_env()

from core.entry_console import main

if __name__ == "__main__":
    main()
