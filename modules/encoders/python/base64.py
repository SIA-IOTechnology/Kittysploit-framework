#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64

class Module(Encoder):
    
    __info__ = {
		"name": "Python Base64 Encoder",
		"description": "Encodes Python code in base64",
		"author": "KittySploit Team",
		"platform": Platform.PYTHON,
	}	
	
	def encode(self, payload):
		code = base64.b64encode(payload).decode()
		return f"import base64;exec(base64.b64decode('{code}'))"