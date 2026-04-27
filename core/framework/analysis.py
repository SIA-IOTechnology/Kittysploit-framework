#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Analysis - Base class for post-operation analysis and reporting modules
"""

from core.framework.base_module import BaseModule

class Analysis(BaseModule):
    """
    Base class for analysis modules.
    
    These modules perform:
    - Report generation
    - Vulnerability correlation
    - Data exfiltration analysis
    - Relationship mapping
    """
    
    TYPE_MODULE = "analysis"

    def __init__(self, framework=None):
        super().__init__(framework)
    
    def run(self):
        """Must be implemented by analysis modules"""
        raise NotImplementedError("Analysis modules must implement the run() method")
    
    def _exploit(self):
        """Analysis modules perform analysis, not exploitation."""
        try:
            return self.run()
        except Exception as e:
            from core.output_handler import print_error
            print_error(f"Analysis error: {e}")
            return False
