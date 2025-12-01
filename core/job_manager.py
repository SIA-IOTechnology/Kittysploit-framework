#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Global job manager for managing background tasks across the framework
"""

import threading
import os
from datetime import datetime
from typing import Dict, Any, Optional

class GlobalJobManager:
    """Global job manager for managing background tasks"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(GlobalJobManager, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.jobs: Dict[int, Dict[str, Any]] = {}
        self.job_counter = 0
        self.jobs_lock = threading.Lock()
        self._initialized = True
    
    def add_job(self, name: str, description: str = "", target: str = None, module: Any = None) -> Optional[int]:
        """Add a new job to the job list"""
        try:
            with self.jobs_lock:
                self.job_counter += 1
                job_id = self.job_counter
                
                job = {
                    'id': job_id,
                    'name': name,
                    'description': description,
                    'status': 'running',
                    'started_at': datetime.utcnow(),
                    'target': target,
                    'module': module,
                    'output': '',
                    'error': '',
                    'pid': os.getpid()  # Use current process PID
                }
                
                self.jobs[job_id] = job
                return job_id
                
        except Exception as e:
            print(f"Error adding job: {e}")
            return None
    
    def update_job_status(self, job_id: int, status: str, output: str = "", error: str = "") -> bool:
        """Update job status and information"""
        try:
            with self.jobs_lock:
                if job_id not in self.jobs:
                    return False
                
                job = self.jobs[job_id]
                job['status'] = status
                
                if output:
                    job['output'] += output
                if error:
                    job['error'] += error
                
                if status == 'completed':
                    job['completed_at'] = datetime.utcnow()
                elif status == 'killed':
                    job['killed_at'] = datetime.utcnow()
                
                return True
                
        except Exception as e:
            print(f"Error updating job status: {e}")
            return False
    
    def get_job(self, job_id: int) -> Optional[Dict[str, Any]]:
        """Get job by ID"""
        with self.jobs_lock:
            return self.jobs.get(job_id)
    
    def get_all_jobs(self) -> Dict[int, Dict[str, Any]]:
        """Get all jobs"""
        with self.jobs_lock:
            return self.jobs.copy()
    
    def kill_job(self, job_id: int) -> bool:
        """Kill a job"""
        try:
            with self.jobs_lock:
                if job_id not in self.jobs:
                    return False
                
                job = self.jobs[job_id]
                if job['status'] == 'running':
                    # Try to stop the module if it has a shutdown method
                    if job.get('module') and hasattr(job['module'], 'shutdown'):
                        try:
                            job['module'].shutdown()
                        except Exception as e:
                            print(f"Error calling shutdown on module: {e}")
                    
                    job['status'] = 'killed'
                    job['killed_at'] = datetime.utcnow()
                    return True
                
                return False
                
        except Exception as e:
            print(f"Error killing job: {e}")
            return False
    
    def clear_completed_jobs(self) -> int:
        """Clear completed jobs from the list"""
        try:
            with self.jobs_lock:
                completed_jobs = [job_id for job_id, job in self.jobs.items() 
                                if job['status'] in ['completed', 'killed']]
                
                for job_id in completed_jobs:
                    del self.jobs[job_id]
                
                return len(completed_jobs)
                
        except Exception as e:
            print(f"Error clearing completed jobs: {e}")
            return 0

# Global instance
global_job_manager = GlobalJobManager()
