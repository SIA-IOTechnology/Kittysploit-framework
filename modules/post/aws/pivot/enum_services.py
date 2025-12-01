#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS Services Enumeration Module
Author: KittySploit Team
Version: 1.0.0

This module discovers all AWS services in use and provides a comprehensive overview.
"""

from kittysploit import *
import json
from core.output_handler import print_info, print_success, print_error, print_warning

class Module(Post):
    """Enumerate all AWS services in use"""
    
    __info__ = {
        "name": "Enumerate AWS Services",
        "description": "Discover all AWS services in use across the account",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.AWS,
    }
    
    enum_ec2 = OptBool(True, "Enumerate EC2", False)
    enum_s3 = OptBool(True, "Enumerate S3", False)
    enum_lambda = OptBool(True, "Enumerate Lambda", False)
    enum_rds = OptBool(True, "Enumerate RDS", False)
    enum_iam = OptBool(True, "Enumerate IAM", False)
    enum_vpc = OptBool(True, "Enumerate VPC", False)
    enum_cloudformation = OptBool(True, "Enumerate CloudFormation", False)
    enum_cloudtrail = OptBool(True, "Enumerate CloudTrail", False)
    enum_other = OptBool(True, "Enumerate other services (DynamoDB, SNS, SQS, etc.)", False)
    output_file = OptString("", "Output file to save results (JSON format)", False)
    
    def run(self):
        """Run the services enumeration"""
        try:
            results = {
                'services': {},
                'summary': {}
            }
            
            print_info("Starting AWS services enumeration...")
            print_info("=" * 80)
            
            # EC2
            if self.enum_ec2.value:
                print_info("\n[1] Enumerating EC2...")
                ec2_data = self._enum_ec2()
                if ec2_data:
                    results['services']['ec2'] = ec2_data
                    count = len(ec2_data.get('instances', []))
                    results['summary']['ec2_instances'] = count
                    print_success(f"Found {count} EC2 instances")
            
            # S3
            if self.enum_s3.value:
                print_info("\n[2] Enumerating S3...")
                s3_data = self._enum_s3()
                if s3_data:
                    results['services']['s3'] = s3_data
                    count = len(s3_data.get('buckets', []))
                    results['summary']['s3_buckets'] = count
                    print_success(f"Found {count} S3 buckets")
            
            # Lambda
            if self.enum_lambda.value:
                print_info("\n[3] Enumerating Lambda...")
                lambda_data = self._enum_lambda()
                if lambda_data:
                    results['services']['lambda'] = lambda_data
                    count = len(lambda_data.get('functions', []))
                    results['summary']['lambda_functions'] = count
                    print_success(f"Found {count} Lambda functions")
            
            # RDS
            if self.enum_rds.value:
                print_info("\n[4] Enumerating RDS...")
                rds_data = self._enum_rds()
                if rds_data:
                    results['services']['rds'] = rds_data
                    count = len(rds_data.get('instances', []))
                    results['summary']['rds_instances'] = count
                    print_success(f"Found {count} RDS instances")
            
            # IAM
            if self.enum_iam.value:
                print_info("\n[5] Enumerating IAM...")
                iam_data = self._enum_iam()
                if iam_data:
                    results['services']['iam'] = iam_data
                    users = len(iam_data.get('users', []))
                    roles = len(iam_data.get('roles', []))
                    results['summary']['iam_users'] = users
                    results['summary']['iam_roles'] = roles
                    print_success(f"Found {users} IAM users, {roles} IAM roles")
            
            # VPC
            if self.enum_vpc.value:
                print_info("\n[6] Enumerating VPC...")
                vpc_data = self._enum_vpc()
                if vpc_data:
                    results['services']['vpc'] = vpc_data
                    count = len(vpc_data.get('vpcs', []))
                    results['summary']['vpcs'] = count
                    print_success(f"Found {count} VPCs")
            
            # CloudFormation
            if self.enum_cloudformation.value:
                print_info("\n[7] Enumerating CloudFormation...")
                cf_data = self._enum_cloudformation()
                if cf_data:
                    results['services']['cloudformation'] = cf_data
                    count = len(cf_data.get('stacks', []))
                    results['summary']['cloudformation_stacks'] = count
                    print_success(f"Found {count} CloudFormation stacks")
            
            # CloudTrail
            if self.enum_cloudtrail.value:
                print_info("\n[8] Enumerating CloudTrail...")
                trail_data = self._enum_cloudtrail()
                if trail_data:
                    results['services']['cloudtrail'] = trail_data
                    count = len(trail_data.get('trails', []))
                    results['summary']['cloudtrail_trails'] = count
                    print_success(f"Found {count} CloudTrail trails")
            
            # Other services
            if self.enum_other.value:
                print_info("\n[9] Enumerating other services...")
                other_data = self._enum_other_services()
                if other_data:
                    results['services']['other'] = other_data
                    for service, count in other_data.items():
                        if count > 0:
                            print_success(f"Found {count} {service} resources")
            
            # Summary
            print_info("\n" + "=" * 80)
            print_info("SERVICES ENUMERATION SUMMARY")
            print_info("=" * 80)
            
            for key, value in results['summary'].items():
                print_info(f"  {key}: {value}")
            
            # Service count
            services_found = len([s for s in results['services'].values() if s])
            print_success(f"\nTotal services with resources: {services_found}")
            
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
    
    def _enum_ec2(self):
        """Enumerate EC2 resources"""
        cmd = "aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,InstanceType,PublicIpAddress,PrivateIpAddress]' --output json 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                instances = json.loads(result)
                # Flatten the nested structure
                flat_instances = []
                for reservation in instances:
                    for instance in reservation:
                        if len(instance) >= 5:
                            flat_instances.append({
                                'InstanceId': instance[0],
                                'State': instance[1],
                                'InstanceType': instance[2],
                                'PublicIpAddress': instance[3] if instance[3] else 'N/A',
                                'PrivateIpAddress': instance[4] if instance[4] else 'N/A'
                            })
                return {'instances': flat_instances}
            except:
                pass
        return None
    
    def _enum_s3(self):
        """Enumerate S3 resources"""
        cmd = "aws s3api list-buckets --query 'Buckets[*].[Name,CreationDate]' --output json 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                buckets = json.loads(result)
                flat_buckets = []
                for bucket in buckets:
                    if len(bucket) >= 2:
                        flat_buckets.append({
                            'Name': bucket[0],
                            'CreationDate': str(bucket[1])
                        })
                return {'buckets': flat_buckets}
            except:
                pass
        return None
    
    def _enum_lambda(self):
        """Enumerate Lambda resources"""
        cmd = "aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,LastModified]' --output json 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                functions = json.loads(result)
                flat_functions = []
                for func in functions:
                    if len(func) >= 3:
                        flat_functions.append({
                            'FunctionName': func[0],
                            'Runtime': func[1],
                            'LastModified': str(func[2])
                        })
                return {'functions': flat_functions}
            except:
                pass
        return None
    
    def _enum_rds(self):
        """Enumerate RDS resources"""
        cmd = "aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,Engine,DBInstanceStatus,Endpoint.Address]' --output json 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                instances = json.loads(result)
                flat_instances = []
                for inst in instances:
                    if len(inst) >= 3:
                        flat_instances.append({
                            'DBInstanceIdentifier': inst[0],
                            'Engine': inst[1],
                            'Status': inst[2],
                            'Endpoint': inst[3] if len(inst) > 3 and inst[3] else 'N/A'
                        })
                return {'instances': flat_instances}
            except:
                pass
        return None
    
    def _enum_iam(self):
        """Enumerate IAM resources"""
        users_cmd = "aws iam list-users --query 'Users[*].UserName' --output json 2>/dev/null"
        roles_cmd = "aws iam list-roles --query 'Roles[*].RoleName' --output json 2>/dev/null"
        
        users_result = self.cmd_execute(users_cmd)
        roles_result = self.cmd_execute(roles_cmd)
        
        users = []
        roles = []
        
        if users_result:
            try:
                users = json.loads(users_result)
            except:
                pass
        
        if roles_result:
            try:
                roles = json.loads(roles_result)
            except:
                pass
        
        return {'users': users, 'roles': roles} if (users or roles) else None
    
    def _enum_vpc(self):
        """Enumerate VPC resources"""
        cmd = "aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,CidrBlock,IsDefault]' --output json 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                vpcs = json.loads(result)
                flat_vpcs = []
                for vpc in vpcs:
                    if len(vpc) >= 3:
                        flat_vpcs.append({
                            'VpcId': vpc[0],
                            'CidrBlock': vpc[1],
                            'IsDefault': vpc[2]
                        })
                return {'vpcs': flat_vpcs}
            except:
                pass
        return None
    
    def _enum_cloudformation(self):
        """Enumerate CloudFormation resources"""
        cmd = "aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE --query 'StackSummaries[*].[StackName,StackStatus,CreationTime]' --output json 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                stacks = json.loads(result)
                flat_stacks = []
                for stack in stacks:
                    if len(stack) >= 3:
                        flat_stacks.append({
                            'StackName': stack[0],
                            'Status': stack[1],
                            'CreationTime': str(stack[2])
                        })
                return {'stacks': flat_stacks}
            except:
                pass
        return None
    
    def _enum_cloudtrail(self):
        """Enumerate CloudTrail resources"""
        cmd = "aws cloudtrail list-trails --query 'TrailList[*].[Name,HomeRegion]' --output json 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                trails = json.loads(result)
                flat_trails = []
                for trail in trails:
                    if len(trail) >= 2:
                        flat_trails.append({
                            'Name': trail[0],
                            'HomeRegion': trail[1]
                        })
                return {'trails': flat_trails}
            except:
                pass
        return None
    
    def _enum_other_services(self):
        """Enumerate other AWS services"""
        other_services = {}
        
        # DynamoDB
        try:
            cmd = "aws dynamodb list-tables --output json 2>/dev/null"
            result = self.cmd_execute(cmd)
            if result:
                data = json.loads(result)
                other_services['dynamodb_tables'] = len(data.get('TableNames', []))
        except:
            other_services['dynamodb_tables'] = 0
        
        # SNS Topics
        try:
            cmd = "aws sns list-topics --query 'Topics[*].TopicArn' --output json 2>/dev/null"
            result = self.cmd_execute(cmd)
            if result:
                data = json.loads(result)
                other_services['sns_topics'] = len(data) if isinstance(data, list) else 0
        except:
            other_services['sns_topics'] = 0
        
        # SQS Queues
        try:
            cmd = "aws sqs list-queues --output json 2>/dev/null"
            result = self.cmd_execute(cmd)
            if result:
                data = json.loads(result)
                other_services['sqs_queues'] = len(data.get('QueueUrls', []))
        except:
            other_services['sqs_queues'] = 0
        
        # ECS Clusters
        try:
            cmd = "aws ecs list-clusters --output json 2>/dev/null"
            result = self.cmd_execute(cmd)
            if result:
                data = json.loads(result)
                other_services['ecs_clusters'] = len(data.get('clusterArns', []))
        except:
            other_services['ecs_clusters'] = 0
        
        # EKS Clusters
        try:
            cmd = "aws eks list-clusters --output json 2>/dev/null"
            result = self.cmd_execute(cmd)
            if result:
                data = json.loads(result)
                other_services['eks_clusters'] = len(data.get('clusters', []))
        except:
            other_services['eks_clusters'] = 0
        
        return other_services

