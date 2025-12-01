#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Jobs command implementation for managing background tasks
"""

import argparse
import json
import time
import threading
from datetime import datetime
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_table

class JobsCommand(BaseCommand):
    """Command to manage background jobs and tasks"""
    
    @property
    def name(self) -> str:
        return "jobs"
    
    @property
    def description(self) -> str:
        return "Manage background jobs and tasks"
    
    @property
    def usage(self) -> str:
        return "jobs [--list] [--kill] [--info] [--kill-all] [--clear]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command allows you to manage background jobs and tasks, similar to Metasploit's
jobs command. You can list, monitor, and kill background processes.

Options:
    --list, -l           List all active jobs
    --kill, -k <id>      Kill a specific job by ID
    --info, -i <id>      Show detailed information about a job
    --kill-all           Kill all active jobs
    --clear              Clear completed jobs from the list
    --json               Output in JSON format
    --watch              Watch jobs in real-time (auto-refresh)

Examples:
    jobs --list                          # List all active jobs
    jobs --info 1                        # Show details for job ID 1
    jobs --kill 1                        # Kill job ID 1
    jobs --kill-all                      # Kill all jobs
    jobs --clear                         # Clear completed jobs
    jobs --watch                         # Watch jobs in real-time
        """
    
    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()
        # Use the global job manager instead of local jobs
        from core.job_manager import global_job_manager
        self.job_manager = global_job_manager
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command parser"""
        parser = argparse.ArgumentParser(
            description="Manage background jobs and tasks",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  jobs --list                          # List all active jobs
  jobs --info 1                        # Show details for job ID 1
  jobs --kill 1                        # Kill job ID 1
  jobs --kill-all                      # Kill all jobs
  jobs --clear                         # Clear completed jobs
  jobs --watch                         # Watch jobs in real-time
            """
        )
        
        # Action arguments
        parser.add_argument("--list", "-l", action="store_true", help="List all active jobs")
        parser.add_argument("--kill", "-k", dest="kill_id", type=int, help="Kill a specific job by ID")
        parser.add_argument("--info", "-i", dest="info_id", type=int, help="Show detailed job information")
        parser.add_argument("--kill-all", action="store_true", help="Kill all active jobs")
        parser.add_argument("--clear", action="store_true", help="Clear completed jobs")
        parser.add_argument("--watch", action="store_true", help="Watch jobs in real-time")
        
        # Output options
        parser.add_argument("--json", action="store_true", help="Output in JSON format")
        
        return parser
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the jobs command"""
        try:
            parsed_args = self.parser.parse_args(args)
        except SystemExit:
            return True
        
        try:
            if parsed_args.watch:
                return self._watch_jobs(parsed_args)
            elif parsed_args.kill_id:
                return self._kill_job(parsed_args.kill_id)
            elif parsed_args.info_id:
                return self._show_job_info(parsed_args.info_id)
            elif parsed_args.kill_all:
                return self._kill_all_jobs()
            elif parsed_args.clear:
                return self._clear_jobs()
            else:
                # Default: list jobs
                return self._list_jobs(parsed_args)
                    
        except Exception as e:
            print_error(f"Error executing jobs command: {str(e)}")
            return False
    
    def _list_jobs(self, parsed_args):
        """List all jobs"""
        try:
            jobs = self.job_manager.get_all_jobs()
            
            if not jobs:
                print_info("No jobs found")
                return True
            
            if parsed_args.json:
                # JSON output
                jobs_data = []
                for job_id, job in jobs.items():
                    jobs_data.append({
                        'id': job_id,
                        'name': job['name'],
                        'status': job['status'],
                        'started_at': job['started_at'].isoformat(),
                        'pid': job.get('pid'),
                        'description': job.get('description', '')
                    })
                print(json.dumps(jobs_data, indent=2))
            else:
                # Table output - no Description column, all fields complete, no truncation
                headers = ["ID", "Name", "Status", "Started", "PID"]
                rows = []
                
                for job_id, job in sorted(jobs.items()):
                    # Format started time - full format
                    started = job['started_at'].strftime("%H:%M:%S")
                    
                    # Format PID - complete value, show N/A if None
                    pid_value = job.get('pid')
                    pid = str(pid_value) if pid_value is not None else 'N/A'
                    
                    # Format status - full status name, no truncation
                    status = job['status'].upper()
                    
                    rows.append([
                        str(job_id),
                        job['name'],
                        status,
                        started,
                        pid
                    ])
                
                # Custom formatting to ensure no truncation
                # Calculate column widths based on actual content
                col_widths = []
                for i, header in enumerate(headers):
                    max_width = len(str(header))
                    for row in rows:
                        if i < len(row):
                            max_width = max(max_width, len(str(row[i])))
                    col_widths.append(max_width)
                
                # Build header line
                header_parts = []
                for i, header in enumerate(headers):
                    header_parts.append(str(header).ljust(col_widths[i]))
                header_line = " | ".join(header_parts)
                
                # Print header
                print_info(header_line)
                print_info("-" * len(header_line))
                
                # Print rows - no truncation, all values complete
                for row in rows:
                    row_parts = []
                    for i in range(len(headers)):
                        cell_value = str(row[i] if i < len(row) else "")
                        row_parts.append(cell_value.ljust(col_widths[i]))
                    row_line = " | ".join(row_parts)
                    print_info(row_line)
                
                print_info(f"Found {len(jobs)} jobs")
            
            return True
            
        except Exception as e:
            print_error(f"Error listing jobs: {str(e)}")
            return False
    
    def _show_job_info(self, job_id):
        """Show detailed information about a job"""
        try:
            job = self.job_manager.get_job(job_id)
            if not job:
                print_error(f"Job {job_id} not found")
                return False
            
            print_info(f"Job Information - ID: {job_id}")
            print_info("=" * 50)
            print_info(f"Name: {job['name']}")
            print_info(f"Status: {job['status'].upper()}")
            print_info(f"Started: {job['started_at'].strftime('%Y-%m-%d %H:%M:%S')}")
            print_info(f"PID: {job.get('pid', 'N/A')}")
            print_info(f"Description: {job.get('description', 'N/A')}")
            
            if job.get('output'):
                print_info(f"\nOutput:")
                print_info(f"{job['output']}")
            
            if job.get('error'):
                print_info(f"\nError:")
                print_error(f"{job['error']}")
            
            return True
            
        except Exception as e:
            print_error(f"Error showing job info: {str(e)}")
            return False
    
    def _kill_job(self, job_id):
        """Kill a specific job"""
        try:
            job = self.job_manager.get_job(job_id)
            if not job:
                print_error(f"Job {job_id} not found")
                return False
            
            if job['status'] == 'completed':
                print_warning(f"Job {job_id} is already completed")
                return True
            
            if job['status'] == 'killed':
                print_warning(f"Job {job_id} is already killed")
                return True
            
            # Try to kill the process if it has a PID
            if 'pid' in job and job['pid']:
                try:
                    import os
                    import signal
                    os.kill(job['pid'], signal.SIGTERM)
                    print_success(f"Sent SIGTERM to job {job_id} (PID: {job['pid']})")
                except ProcessLookupError:
                    print_warning(f"Process {job['pid']} not found")
                except Exception as e:
                    print_warning(f"Could not kill process {job['pid']}: {e}")
            
            # Use the job manager to kill the job
            if self.job_manager.kill_job(job_id):
                print_success(f"Job {job_id} killed successfully")
                return True
            else:
                print_error(f"Failed to kill job {job_id}")
                return False
                
        except Exception as e:
            print_error(f"Error killing job: {str(e)}")
            return False
    
    def _kill_all_jobs(self):
        """Kill all active jobs"""
        try:
            jobs = self.job_manager.get_all_jobs()
            killed_count = 0
            
            for job_id, job in jobs.items():
                if job['status'] in ['running', 'pending']:
                    if self.job_manager.kill_job(job_id):
                        killed_count += 1
            
            print_success(f"Killed {killed_count} jobs")
            return True
                
        except Exception as e:
            print_error(f"Error killing all jobs: {str(e)}")
            return False
    
    def _clear_jobs(self):
        """Clear completed and killed jobs"""
        try:
            cleared_count = self.job_manager.clear_completed_jobs()
            print_success(f"Cleared {cleared_count} jobs")
            return True
                
        except Exception as e:
            print_error(f"Error clearing jobs: {str(e)}")
            return False
    
    def _watch_jobs(self, parsed_args):
        """Watch jobs in real-time"""
        try:
            import time
            
            print_info("Watching jobs (Press Ctrl+C to stop)...")
            
            try:
                while True:
                    # Clear screen (works on most terminals)
                    print_info("\033[2J\033[H")
                    
                    # Show current time
                    print_info(f"Jobs Status - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    print_info("=" * 50)
                    
                    # List jobs
                    self._list_jobs(parsed_args)
                    
                    # Wait before next refresh
                    time.sleep(2)
                    
            except KeyboardInterrupt:
                print_info("\nStopped watching jobs")
                return True
                
        except Exception as e:
            print_error(f"Error watching jobs: {str(e)}")
            return False
    
    
    def get_job(self, job_id):
        """Get job information"""
        try:
            with self.jobs_lock:
                return self.jobs.get(job_id)
        except Exception as e:
            print_error(f"Error getting job: {str(e)}")
            return None
    
    def get_active_jobs(self):
        """Get list of active job IDs"""
        try:
            with self.jobs_lock:
                return [job_id for job_id, job in self.jobs.items() 
                       if job['status'] in ['pending', 'running']]
        except Exception as e:
            print_error(f"Error getting active jobs: {str(e)}")
            return []
