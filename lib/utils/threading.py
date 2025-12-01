#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Threading library for KittySploit
Provides threading capabilities for various tasks
"""

from core.framework.base_module import BaseModule
from core.framework.option import OptInteger
from core.output_handler import print_error
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

class Thread_module(BaseModule):
        
    max_threads = OptInteger(48, "Number of max threads", required=True, advanced=False)
    
    def __init__(self):
        super().__init__()
        self.lock = Lock()

    def run_in_threads(self, func, iterable):
        results = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(func, item) for item in iterable]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        with self.lock:
                            results.append(result)
                except Exception as e:
                    print_error(e)
        return results