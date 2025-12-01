#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS EC2 Enumeration Module
Author: KittySploit Team
Version: 1.0.0

This module enumerates EC2 instances, security groups, and related resources.
"""

from kittysploit import *
import json
from core.output_handler import print_info, print_success, print_error, print_warning

class Module(Post):
    """Enumerate AWS EC2 instances and resources"""
    
    __info__ = {
        "name": "Enumerate AWS EC2",
        "description": "Enumerate EC2 instances, security groups, and related resources",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.AWS,
    }
    
    enum_instances = OptBool(True, "Enumerate EC2 instances", False)
    enum_security_groups = OptBool(True, "Enumerate security groups", False)
    enum_key_pairs = OptBool(True, "Enumerate key pairs", False)
    enum_images = OptBool(False, "Enumerate AMI images", False)
    enum_snapshots = OptBool(False, "Enumerate EBS snapshots", False)
    check_public_ips = OptBool(True, "Check for public IP addresses", False)
    output_file = OptString("", "Output file to save results (JSON format)", False)
    
    def run(self):
        """Run the EC2 enumeration"""
        try:
            results = {}
            
            print_info("Starting AWS EC2 enumeration...")
            print_info("=" * 80)
            
            # Enumerate instances
            if self.enum_instances.value:
                print_info("\n[1] Enumerating EC2 instances...")
                instances = self._enum_instances()
                if instances:
                    results['instances'] = instances
                    print_success(f"Found {len(instances)} EC2 instances")
                    
                    for instance in instances:
                        instance_id = instance.get('InstanceId', 'Unknown')
                        state = instance.get('State', {}).get('Name', 'Unknown')
                        instance_type = instance.get('InstanceType', 'Unknown')
                        public_ip = instance.get('PublicIpAddress', 'N/A')
                        private_ip = instance.get('PrivateIpAddress', 'N/A')
                        
                        print_info(f"  - {instance_id} ({state})")
                        print_info(f"    Type: {instance_type}, Private IP: {private_ip}, Public IP: {public_ip}")
                        
                        if public_ip and public_ip != 'N/A' and self.check_public_ips.value:
                            print_warning(f"    ⚠️  Public IP: {public_ip}")
                else:
                    print_info("No instances found or access denied")
            
            # Enumerate security groups
            if self.enum_security_groups.value:
                print_info("\n[2] Enumerating security groups...")
                security_groups = self._enum_security_groups()
                if security_groups:
                    results['security_groups'] = security_groups
                    print_success(f"Found {len(security_groups)} security groups")
                    
                    for sg in security_groups[:10]:  # Show first 10
                        sg_id = sg.get('GroupId', 'Unknown')
                        sg_name = sg.get('GroupName', 'Unknown')
                        print_info(f"  - {sg_name} ({sg_id})")
                        
                        # Check for overly permissive rules
                        ingress = sg.get('IpPermissions', [])
                        for rule in ingress:
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    port = rule.get('FromPort', 'all')
                                    print_warning(f"    ⚠️  Open to world: port {port}")
                    
                    if len(security_groups) > 10:
                        print_info(f"  ... and {len(security_groups) - 10} more")
                else:
                    print_info("No security groups found or access denied")
            
            # Enumerate key pairs
            if self.enum_key_pairs.value:
                print_info("\n[3] Enumerating key pairs...")
                key_pairs = self._enum_key_pairs()
                if key_pairs:
                    results['key_pairs'] = key_pairs
                    print_success(f"Found {len(key_pairs)} key pairs")
                    for kp in key_pairs:
                        print_info(f"  - {kp.get('KeyName', 'Unknown')}")
                else:
                    print_info("No key pairs found or access denied")
            
            # Enumerate images
            if self.enum_images.value:
                print_info("\n[4] Enumerating AMI images...")
                images = self._enum_images()
                if images:
                    results['images'] = images
                    print_success(f"Found {len(images)} AMI images")
                    for img in images[:10]:
                        print_info(f"  - {img.get('ImageId', 'Unknown')} ({img.get('Name', 'Unknown')})")
                    if len(images) > 10:
                        print_info(f"  ... and {len(images) - 10} more")
                else:
                    print_info("No images found or access denied")
            
            # Enumerate snapshots
            if self.enum_snapshots.value:
                print_info("\n[5] Enumerating EBS snapshots...")
                snapshots = self._enum_snapshots()
                if snapshots:
                    results['snapshots'] = snapshots
                    print_success(f"Found {len(snapshots)} EBS snapshots")
                    for snap in snapshots[:10]:
                        print_info(f"  - {snap.get('SnapshotId', 'Unknown')} ({snap.get('VolumeSize', 0)} GB)")
                    if len(snapshots) > 10:
                        print_info(f"  ... and {len(snapshots) - 10} more")
                else:
                    print_info("No snapshots found or access denied")
            
            # Summary
            print_info("\n" + "=" * 80)
            print_info("ENUMERATION SUMMARY")
            print_info("=" * 80)
            print_success(f"Enumerated:")
            print_info(f"  - Instances: {len(results.get('instances', []))}")
            print_info(f"  - Security Groups: {len(results.get('security_groups', []))}")
            print_info(f"  - Key Pairs: {len(results.get('key_pairs', []))}")
            if self.enum_images.value:
                print_info(f"  - Images: {len(results.get('images', []))}")
            if self.enum_snapshots.value:
                print_info(f"  - Snapshots: {len(results.get('snapshots', []))}")
            
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
    
    def _enum_instances(self):
        """Enumerate EC2 instances"""
        cmd = "aws ec2 describe-instances 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                instances = []
                for reservation in data.get('Reservations', []):
                    instances.extend(reservation.get('Instances', []))
                return instances
            except:
                pass
        
        # Try Python boto3
        python_cmd = """
python3 -c "
import boto3, json
try:
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances()
    instances = []
    for reservation in response.get('Reservations', []):
        instances.extend(reservation.get('Instances', []))
    print(json.dumps(instances))
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
    
    def _enum_security_groups(self):
        """Enumerate security groups"""
        cmd = "aws ec2 describe-security-groups 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('SecurityGroups', [])
            except:
                pass
        
        # Try Python boto3
        python_cmd = """
python3 -c "
import boto3, json
try:
    ec2 = boto3.client('ec2')
    response = ec2.describe_security_groups()
    print(json.dumps(response.get('SecurityGroups', [])))
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
    
    def _enum_key_pairs(self):
        """Enumerate key pairs"""
        cmd = "aws ec2 describe-key-pairs 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('KeyPairs', [])
            except:
                pass
        return []
    
    def _enum_images(self):
        """Enumerate AMI images"""
        cmd = "aws ec2 describe-images --owners self 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('Images', [])
            except:
                pass
        return []
    
    def _enum_snapshots(self):
        """Enumerate EBS snapshots"""
        cmd = "aws ec2 describe-snapshots --owner-ids self 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('Snapshots', [])
            except:
                pass
        return []


