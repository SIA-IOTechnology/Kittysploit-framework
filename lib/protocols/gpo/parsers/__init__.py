#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.protocols.gpo.parsers.groups_xml import parse_groups_xml
from lib.protocols.gpo.parsers.gpttmpl import parse_gpttmpl_group_membership

__all__ = ["parse_groups_xml", "parse_gpttmpl_group_membership"]
