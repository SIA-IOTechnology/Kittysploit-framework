#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Simple example Plugin for KittySploit
"""

from kittysploit import *
import shlex

class ExamplePlugin(Plugin):
    """Simple example plugin for demonstration"""
    
    __info__ = {
        "name": "example",
        "description": "A simple example plugin for demonstration",
        "version": "1.0.0",
        "author": "KittySploit Team",
        "dependencies": []
    }
    
    def __init__(self, framework=None):
        super().__init__(framework)
    
    def run(self, *args, **kwargs):
        """Simple plugin execution"""
        parser = ModuleArgumentParser(description=self.__doc__, prog="example")
        parser.add_argument("-m", "--message", dest="message", help="Message to display", metavar="<message>", type=str)
        parser.add_argument("-c", "--count", dest="count", help="Number of times to repeat", metavar="<count>", type=int, default=1)
        # Help is automatically added by ModuleArgumentParser

        if not args or not args[0]:
            parser.print_help()
            return True

        try:
            pargs = parser.parse_args(shlex.split(args[0]))

            if getattr(pargs, 'help', False):
                parser.print_help()
                return True

            message = pargs.message or "Hello from Example Plugin!"
            count = pargs.count

            print_success(f"Example Plugin executed!")
            print_info(f"Message: {message}")
            print_info(f"Count: {count}")
            
            for i in range(count):
                print_info(f"  {i+1}. {message}")

            return True

        except Exception as e:
            print_error(f"An error occurred: {e}")
            return False
