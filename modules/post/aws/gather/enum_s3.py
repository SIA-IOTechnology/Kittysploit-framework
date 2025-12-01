#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS S3 Enumeration Module
Author: KittySploit Team
Version: 1.0.0

This module enumerates S3 buckets and their contents.
"""

from kittysploit import *
import json
from core.output_handler import print_info, print_success, print_error, print_warning

class Module(Post):
    """Enumerate AWS S3 buckets and objects"""
    
    __info__ = {
        "name": "Enumerate AWS S3",
        "description": "Enumerate S3 buckets, list objects, and check permissions",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.AWS,
    }
    
    list_buckets = OptBool(True, "List all S3 buckets", False)
    check_permissions = OptBool(True, "Check bucket permissions (ACL, policies)", False)
    list_objects = OptBool(False, "List objects in buckets (can be slow)", False)
    max_objects = OptInteger(100, "Maximum objects to list per bucket", False)
    check_public = OptBool(True, "Check if buckets are publicly accessible", False)
    output_file = OptString("", "Output file to save results (JSON format)", False)
    
    def run(self):
        """Run the S3 enumeration"""
        try:
            results = {}
            
            print_info("Starting AWS S3 enumeration...")
            print_info("=" * 80)
            
            # List buckets
            if self.list_buckets.value:
                print_info("\n[1] Listing S3 buckets...")
                buckets = self._list_buckets()
                if buckets:
                    results['buckets'] = buckets
                    print_success(f"Found {len(buckets)} S3 buckets")
                    for bucket in buckets:
                        name = bucket.get('Name', 'Unknown')
                        created = bucket.get('CreationDate', 'Unknown')
                        print_info(f"  - {name} (created: {created})")
                else:
                    print_info("No buckets found or access denied")
            
            # Check permissions and list objects
            if buckets and (self.check_permissions.value or self.list_objects.value or self.check_public.value):
                print_info("\n[2] Analyzing buckets...")
                for bucket in buckets:
                    bucket_name = bucket.get('Name')
                    if not bucket_name:
                        continue
                    
                    print_info(f"\n[*] Analyzing bucket: {bucket_name}")
                    bucket_info = {'name': bucket_name}
                    
                    # Check permissions
                    if self.check_permissions.value:
                        print_info(f"  Checking permissions...")
                        acl = self._get_bucket_acl(bucket_name)
                        policy = self._get_bucket_policy(bucket_name)
                        if acl:
                            bucket_info['acl'] = acl
                        if policy:
                            bucket_info['policy'] = policy
                    
                    # Check if public
                    if self.check_public.value:
                        is_public = self._check_bucket_public(bucket_name)
                        bucket_info['is_public'] = is_public
                        if is_public:
                            print_warning(f"  ⚠️  Bucket {bucket_name} is PUBLIC!")
                    
                    # List objects
                    if self.list_objects.value:
                        print_info(f"  Listing objects (max {self.max_objects.value})...")
                        objects = self._list_bucket_objects(bucket_name, self.max_objects.value)
                        if objects:
                            bucket_info['objects'] = objects
                            bucket_info['object_count'] = len(objects)
                            print_info(f"  Found {len(objects)} objects")
                            # Show first few objects
                            for obj in objects[:5]:
                                key = obj.get('Key', 'Unknown')
                                size = obj.get('Size', 0)
                                print_info(f"    - {key} ({size} bytes)")
                            if len(objects) > 5:
                                print_info(f"    ... and {len(objects) - 5} more")
                    
                    results['buckets'].append(bucket_info)
            
            # Summary
            print_info("\n" + "=" * 80)
            print_info("ENUMERATION SUMMARY")
            print_info("=" * 80)
            print_success(f"Found {len(results.get('buckets', []))} S3 buckets")
            
            public_buckets = [b for b in results.get('buckets', []) if b.get('is_public')]
            if public_buckets:
                print_warning(f"⚠️  Found {len(public_buckets)} PUBLIC buckets:")
                for bucket in public_buckets:
                    print_warning(f"  - {bucket.get('name')}")
            
            # Save to file if requested
            if self.output_file.value:
                try:
                    with open(self.output_file.value, 'w') as f:
                        json.dump(results, f, indent=2, default=str)
                    print_success(f"Results saved to {self.output_file.value}")
                except Exception as e:
                    print_error(f"Failed to save results: {e}")
            
            return True
            
        except Exception as e:
            print_error(f"Error during enumeration: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _list_buckets(self):
        """List all S3 buckets"""
        cmd = "aws s3api list-buckets 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('Buckets', [])
            except:
                pass
        
        # Try Python boto3
        python_cmd = """
python3 -c "
import boto3, json
try:
    s3 = boto3.client('s3')
    response = s3.list_buckets()
    print(json.dumps(response.get('Buckets', [])))
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
    
    def _get_bucket_acl(self, bucket_name):
        """Get bucket ACL"""
        cmd = f"aws s3api get-bucket-acl --bucket {bucket_name} 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                return json.loads(result)
            except:
                pass
        return None
    
    def _get_bucket_policy(self, bucket_name):
        """Get bucket policy"""
        cmd = f"aws s3api get-bucket-policy --bucket {bucket_name} 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                policy_str = data.get('Policy', '{}')
                return json.loads(policy_str)
            except:
                pass
        return None
    
    def _check_bucket_public(self, bucket_name):
        """Check if bucket is publicly accessible"""
        # Try to access bucket without credentials
        cmd = f"aws s3 ls s3://{bucket_name} --no-sign-request 2>&1 | head -1"
        result = self.cmd_execute(cmd)
        
        if result and 'AccessDenied' not in result and 'NoSuchBucket' not in result:
            return True
        
        # Check ACL
        acl = self._get_bucket_acl(bucket_name)
        if acl:
            grants = acl.get('Grants', [])
            for grant in grants:
                grantee = grant.get('Grantee', {})
                if grantee.get('Type') == 'Group' and 'AllUsers' in str(grantee):
                    return True
        
        return False
    
    def _list_bucket_objects(self, bucket_name, max_objects=100):
        """List objects in a bucket"""
        cmd = f"aws s3api list-objects-v2 --bucket {bucket_name} --max-items {max_objects} 2>/dev/null"
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
    response = s3.list_objects_v2(Bucket='{bucket_name}', MaxKeys={max_objects})
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


