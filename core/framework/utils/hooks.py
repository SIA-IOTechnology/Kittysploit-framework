#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Callable, List, Dict, Any
from enum import Enum
from core.output_handler import print_error

class HookPoint(Enum):
    BEFORE_MODULE_LOAD = "before_module_load"
    AFTER_MODULE_LOAD = "after_module_load"
    BEFORE_MODULE_EXECUTE = "before_module_execute"
    AFTER_MODULE_EXECUTE = "after_module_execute"
    BEFORE_OPTION_SET = "before_option_set"
    AFTER_OPTION_SET = "after_option_set"

class HookManager:
    """Manage hooks for extensibility"""
    
    def __init__(self):
        self.hooks: Dict[HookPoint, List[Callable]] = {
            hook: [] for hook in HookPoint
        }
    
    def register(self, hook_point: HookPoint, callback: Callable, priority: int = 0):
        """Register a hook"""
        if hook_point not in self.hooks:
            self.hooks[hook_point] = []
        
        self.hooks[hook_point].append({
            "callback": callback,
            "priority": priority
        })
        # Sort by priority (higher first)
        self.hooks[hook_point].sort(key=lambda x: x["priority"], reverse=True)
    
    def execute(self, hook_point: HookPoint, *args, **kwargs) -> Any:
        """Execute hooks for a hook point"""
        if hook_point not in self.hooks:
            return None
        
        result = None
        for hook in self.hooks[hook_point]:
            try:
                result = hook["callback"](*args, **kwargs)
                # If hook returns False, stop execution
                if result is False:
                    break
            except Exception as e:
                print_error(f"Error in hook {hook_point.value}: {e}")
        
        return result
    
    def has_hook(self, hook_point: HookPoint) -> bool:
        """Check if a hook is registered for a hook point"""
        return hook_point in self.hooks and self.hooks[hook_point]