#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

class Module(Workflow):
    
    __info__ = {
        'name': 'Simple Workflow',
        'description': 'Workflow basic demonstration of base features',
        'author': 'KittySploit Team',
    }
    
    # Options
    target = OptString("", "Target host or IP address", required=True)
    verbose = OptBool(False, "Enable verbose output", required=False)
    
    def run(self):

        # Step 1: Ping the target
        ping_step = WorkflowStep(
            module_path="auxiliary/ping_test",
            options={
                "target": self.target,
                "verbose": self.verbose
            },
            name="ping_target",
            description="Connectivity test to target",
            on_success="port_scan",
            on_failure="workflow_end"
        )
        ping_step.map_output("ping_result", "target_reachable")
        ping_step.map_output("response_time", "ping_time")
        
        # Step 2: Basic port scan
        scan_step = WorkflowStep(
            module_path="auxiliary/quick_scan",
            name="port_scan",
            description="Quick scan of common ports",
            on_success="service_check",
            on_failure="workflow_end"
        )
        scan_step.map_input("target", "target_host")
        scan_step.map_output("open_ports", "discovered_ports")
        
        # Step 3: Check services
        service_step = WorkflowStep(
            module_path="auxiliary/service_check",
            name="service_check",
            description="Check services on open ports",
            on_success=None,
            on_failure=None
        )
        service_step.map_input("discovered_ports", "ports_to_check")
        service_step.map_output("services", "detected_services")
        
        # Add all steps to the workflow
        self.add_step(ping_step)
        self.add_step(scan_step)
        self.add_step(service_step)
        
        # Define the start step
        self.set_start_step("ping_target")