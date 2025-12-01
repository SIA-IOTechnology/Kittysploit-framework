#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import json
import os
from typing import List, Dict, Any, Optional, Callable
from core.framework.base_module import BaseModule
from core.output_handler import print_info, print_error, print_success, print_warning

class WorkflowStep:
    """Represents a step in a workflow"""
    
    def __init__(self, module_path, options=None, name=None, description=None, 
                 condition=None, on_success=None, on_failure=None):
        """
        Initialize a workflow step
        
        Args:
            module_path: Path of the module to execute
            options: Options to define for the module
            name: Name of the step (optional)
            description: Description of the step (optional)
            condition: Function that determines if the step should be executed
            on_success: Name of the next step in case of success
            on_failure: Name of the next step in case of failure
        """
        self.module_path = module_path
        self.options = options or {}
        self.name = name or f"step_{module_path.replace('/', '_')}"
        self.description = description or f"Execution of the module {module_path}"
        self.condition = condition
        self.on_success = on_success
        self.on_failure = on_failure
        self.result = None
        self.executed = False
    
    def should_execute(self, workflow_context):
        """Determine if the step should be executed"""
        if self.condition is None:
            return True
        
        if callable(self.condition):
            return self.condition(workflow_context)
        
        return False
    
    def to_dict(self):
        """Convert the step to a dictionary"""
        data = {
            "module_path": self.module_path,
            "options": self.options,
            "name": self.name,
            "description": self.description,
            "on_success": self.on_success,
            "on_failure": self.on_failure
        }
        
        # Add mappings if they exist
        if hasattr(self, 'output_mapping') and self.output_mapping:
            data["output_mapping"] = self.output_mapping
        
        if hasattr(self, 'input_mapping') and self.input_mapping:
            data["input_mapping"] = self.input_mapping
        
        return data
    
    @classmethod
    def from_dict(cls, data):
        """Create a step from a dictionary"""
        step = cls(
            module_path=data["module_path"],
            options=data.get("options", {}),
            name=data.get("name"),
            description=data.get("description"),
            on_success=data.get("on_success"),
            on_failure=data.get("on_failure")
        )
        
        # Add mappings if they exist
        if "output_mapping" in data:
            step.output_mapping = data["output_mapping"]
        
        if "input_mapping" in data:
            step.input_mapping = data["input_mapping"]
        
        return step

    def set_output_mapping(self, output_mapping):
        """
        Define how the outputs of this step are mapped to the workflow context
        
        Args:
            output_mapping: Dictionary that maps the module attributes to keys in the context
                For example: {"scan_results": "ports_opened"} will store the value of module.scan_results
                in the context under the key "ports_opened"
        """
        self.output_mapping = output_mapping

    def set_input_mapping(self, input_mapping):
        """
        Define how the inputs of this step are mapped from the workflow context
        
        Args:
            input_mapping: Dictionary that maps the keys of the context to the module options
                For example: {"ports_opened": "target_ports"} will use the value of the context "ports_opened"
                to define the "target_ports" option of the module
        """
        self.input_mapping = input_mapping

    def extract_outputs(self, module):
        """
        Extract the outputs of the module according to the defined mapping
        
        Args:
            module: The module that was executed
            
        Returns:
            Dict: Dictionary of extracted outputs
        """
        if not hasattr(self, 'output_mapping') or not self.output_mapping:
            return {}
        
        outputs = {}
        for module_attr, context_key in self.output_mapping.items():
            if hasattr(module, module_attr):
                outputs[context_key] = getattr(module, module_attr)
        
        return outputs

    def apply_inputs(self, module, context):
        """
        Apply inputs from context to module according to the defined mapping
        
        Args:
            module: The module to configure
            context: The workflow context
        """
        if not hasattr(self, 'input_mapping') or not self.input_mapping:
            return
        
        for context_key, module_option in self.input_mapping.items():
            if context_key in context and hasattr(module, module_option):
                setattr(module, module_option, context[context_key])

    def map_output(self, module_attr, context_key):
        """
        Map a module attribute to a key in the context
        
        Args:
            module_attr: Name of the module attribute
            context_key: Key under which to store the value in the context
        """
        if not hasattr(self, 'output_mapping'):
            self.output_mapping = {}
        
        self.output_mapping[module_attr] = context_key
        return self

    def map_input(self, context_key, module_option):
        """
        Map a context key to a module option
        
        Args:
            context_key: Key in the context
            module_option: Name of the module option
        """
        if not hasattr(self, 'input_mapping'):
            self.input_mapping = {}
        
        self.input_mapping[context_key] = module_option
        return self


class Workflow(BaseModule):
    """Base class for workflows"""
    
    def __init__(self, framework=None):
        super().__init__(framework)
        self._type = "workflow"
        self.steps = {}  # Dictionary of steps by name
        self.start_step = None  # Name of the start step
        self.current_step = None  # Current step being executed
        self.context = {}  # Context shared between steps
        self.results = {}  # Results of the steps executed
    
    def add_step(self, step):
        """Add a step to the workflow"""
        self.steps[step.name] = step
        
        # If it's the first step, define it as the start step
        if self.start_step is None:
            self.start_step = step.name
    
    def set_start_step(self, step_name):
        """Define the start step"""
        if step_name in self.steps:
            self.start_step = step_name
        else:
            raise ValueError(f"The step {step_name} does not exist in this workflow")
    
    def run(self):
        """Execute the workflow"""
        raise NotImplementedError("Workflows must implement the run() method")

    def _exploit(self):
        """Execute the workflow"""
        # Call run() to build the workflow steps (if implemented)
        self.run()
        
        # Build workflow if _build_workflow exists and steps are not yet defined
        if not self.steps and hasattr(self, '_build_workflow'):
            self._build_workflow()
        
        if not self.start_step:
            print_error("No start step defined for this workflow")
            return False
        
        if not self.steps:
            print_error("No steps defined for this workflow")
            return False
        
        print_info(f"Starting workflow: {self.name}")
        
        # Initialize the context
        self.context = {
            "start_time": time.time(),
            "results": {},
            "current_step": self.start_step,
            "data": {}  # Data shared between steps
        }
        
        # Start with the start step
        current_step_name = self.start_step
        success = True
        
        while current_step_name:
            if current_step_name not in self.steps:
                print_error(f"Step {current_step_name} not found in the workflow")
                return False
            
            step = self.steps[current_step_name]
            self.current_step = step
            self.context["current_step"] = current_step_name
            
            print_info(f"Executing step: {step.name} - {step.description}")
            
            # Check if the step should be executed
            if not step.should_execute(self.context):
                print_info(f"Step {step.name} skipped (condition not met)")
                
                # Go to the next step in case of success
                current_step_name = step.on_success
                continue
            
            # Load the module
            module = self.framework.load_module(step.module_path)
            if not module:
                print_error(f"Unable to load the module {step.module_path}")
                
                # Go to the next step in case of failure
                current_step_name = step.on_failure
                success = False
                continue
            
            # Configure the options of the module
            for option_name, option_value in step.options.items():
                if hasattr(module, option_name):
                    setattr(module, option_name, option_value)
            
            # Apply the inputs of the context to the module
            if hasattr(step, 'input_mapping') and step.input_mapping:
                step.apply_inputs(module, self.context["data"])
            
            # Execute the module
            try:
                result = module.run()
                step.result = result
                step.executed = True
                
                # Store the result in the context
                self.context["results"][step.name] = result
                self.results[step.name] = result
                
                # Extract the outputs of the module and store them in the context
                if hasattr(step, 'output_mapping') and step.output_mapping:
                    outputs = step.extract_outputs(module)
                    for key, value in outputs.items():
                        self.context["data"][key] = value
                        print_info(f"Data '{key}' extracted and stored in context")
                
                if result:
                    print_success(f"Step {step.name} executed successfully")
                    current_step_name = step.on_success
                else:
                    print_warning(f"Step {step.name} failed")
                    current_step_name = step.on_failure
                    success = False
            
            except Exception as e:
                print_error(f"Error executing step {step.name}: {str(e)}")
                step.result = False
                step.executed = True
                
                # Store the error in the context
                self.context["results"][step.name] = False
                self.context["errors"] = self.context.get("errors", {})
                self.context["errors"][step.name] = str(e)
                self.results[step.name] = False
                
                current_step_name = step.on_failure
                success = False
        
        # Calculate execution duration
        duration = time.time() - self.context["start_time"]
        print_info(f"Workflow finished in {duration:.2f} seconds")
        
        return success
    
    def save(self, filename):
        """Save the workflow to a JSON file"""
        data = {
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "start_step": self.start_step,
            "steps": {name: step.to_dict() for name, step in self.steps.items()}
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
            print_success(f"Workflow saved to {filename}")
            return True
        except Exception as e:
            print_error(f"Error saving workflow: {str(e)}")
            return False
    
    @classmethod
    def load(cls, filename, framework=None):
        """Load a workflow from a JSON file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            workflow = cls(framework)
            workflow.name = data.get("name", "Workflow without name")
            workflow.description = data.get("description", "")
            workflow.author = data.get("author", "")
            
            # Load the steps
            for step_name, step_data in data.get("steps", {}).items():
                step = WorkflowStep.from_dict(step_data)
                workflow.add_step(step)
            
            # Define the start step
            if "start_step" in data and data["start_step"] in workflow.steps:
                workflow.start_step = data["start_step"]
            
            return workflow
        
        except Exception as e:
            print_error(f"Error loading workflow: {str(e)}")
            return None 