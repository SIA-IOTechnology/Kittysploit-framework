#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Registry Marketplace - Système de distribution et gestion d'extensions
"""

__version__ = "1.0.0"

# Import models to ensure they're registered with SQLAlchemy Base
from core.registry import models  # noqa: F401
from core.registry.service import RegistryService  # noqa: F401

