#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import json
import os

class Module(Post):
    
    __info__ = {
        "name": "Upload to S3",
        "description": "Upload files or directories to S3 buckets",
        "author": "KittySploit Team",
        "tags": ["aws", "s3"],
        "session_type": SessionType.AWS,
    }
    
    bucket_name = OptString("", "S3 bucket name (REQUIRED)", True)
    local_path = OptString("", "Local file or directory path to upload (REQUIRED)", True)
    s3_key = OptString("", "S3 object key (filename in bucket, uses local filename if empty)", False)
    make_public = OptBool(False, "Make uploaded objects publicly readable", False)
    content_type = OptString("", "Content type (auto-detected if empty)", False)
    encrypt = OptBool(False, "Enable server-side encryption (SSE)", False)
    
    def run(self):
        """Run the S3 upload"""
        try:
            bucket = self.bucket_name.value
            local_path = self.local_path.value
            
            if not bucket or not local_path:
                print_error("Both bucket_name and local_path are required")
                return False
            
            print_status("Starting S3 upload...")
            print_info("=" * 80)
            print_info(f"Bucket: {bucket}")
            print_info(f"Local path: {local_path}")
            
            # Check if local path exists
            check_cmd = f"test -f {local_path} && echo 'file' || (test -d {local_path} && echo 'directory' || echo 'not found')"
            path_type = self.cmd_execute(check_cmd)
            
            if 'not found' in path_type:
                print_error(f"Local path not found: {local_path}")
                return False
            
            is_directory = 'directory' in path_type
            
            if is_directory:
                # Upload directory
                print_info("\n[1] Uploading directory...")
                success = self._upload_directory(bucket, local_path, self.make_public.value)
            else:
                # Upload single file
                print_info("\n[1] Uploading file...")
                s3_key = self.s3_key.value
                if not s3_key:
                    # Use filename from local path
                    s3_key = os.path.basename(local_path)
                
                success = self._upload_file(bucket, local_path, s3_key, self.make_public.value, self.content_type.value, self.encrypt.value)
            
            if success:
                print_success("Upload completed successfully")
                
                if self.make_public.value:
                    print_warning("⚠️  Uploaded objects are PUBLIC!")
                    print_info(f"  Public URL: https://{bucket}.s3.amazonaws.com/{s3_key if not is_directory else '...'}")
                
                return True
            else:
                print_error("Upload failed")
                return False
            
        except Exception as e:
            print_error(f"Error during upload: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _upload_file(self, bucket, local_path, s3_key, make_public=False, content_type=None, encrypt=False):
        """Upload a single file to S3"""
        cmd = f"aws s3 cp {local_path} s3://{bucket}/{s3_key}"
        
        if make_public:
            cmd += " --acl public-read"
        
        if content_type:
            cmd += f" --content-type {content_type}"
        
        if encrypt:
            cmd += " --sse AES256"
        
        cmd += " 2>&1"
        
        result = self.cmd_execute(cmd)
        
        if result and ('upload' in result.lower() or 'completed' in result.lower() or 'copy' in result.lower()):
            print_success(f"Uploaded: {s3_key}")
            return True
        
        # Check for errors
        if 'error' in result.lower() or 'denied' in result.lower():
            print_error(f"Upload failed: {result}")
            return False
        
        return True
    
    def _upload_directory(self, bucket, local_path, make_public=False):
        """Upload a directory to S3"""
        cmd = f"aws s3 sync {local_path} s3://{bucket}/"
        
        if make_public:
            cmd += " --acl public-read"
        
        cmd += " 2>&1"
        
        print_info(f"Syncing directory to s3://{bucket}/...")
        result = self.cmd_execute(cmd)
        
        if result:
            # Count uploaded files
            count_cmd = f"find {local_path} -type f | wc -l"
            count_result = self.cmd_execute(count_cmd)
            if count_result:
                print_success(f"Uploaded {count_result.strip()} files")
            
            if make_public:
                print_warning("⚠️  All uploaded objects are PUBLIC!")
            
            return True
        
        return False

