#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS VPC Enumeration Module
Author: KittySploit Team
Version: 1.0.0

This module enumerates VPCs, subnets, security groups, and network topology.
"""

from kittysploit import *
import json
from core.output_handler import print_info, print_success, print_error, print_warning

class Module(Post):
    """Enumerate AWS VPCs and network topology"""
    
    __info__ = {
        "name": "Enumerate AWS VPC",
        "description": "Enumerate VPCs, subnets, route tables, and network topology",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "session_type": SessionType.AWS,
    }
    
    enum_vpcs = OptBool(True, "Enumerate VPCs", False)
    enum_subnets = OptBool(True, "Enumerate subnets", False)
    enum_route_tables = OptBool(True, "Enumerate route tables", False)
    enum_internet_gateways = OptBool(True, "Enumerate internet gateways", False)
    enum_nat_gateways = OptBool(True, "Enumerate NAT gateways", False)
    enum_vpc_peering = OptBool(True, "Enumerate VPC peering connections", False)
    map_topology = OptBool(True, "Map network topology", False)
    output_file = OptString("", "Output file to save results (JSON format)", False)
    
    def run(self):
        """Run the VPC enumeration"""
        try:
            results = {}
            
            print_info("Starting AWS VPC enumeration...")
            print_info("=" * 80)
            
            # Enumerate VPCs
            if self.enum_vpcs.value:
                print_info("\n[1] Enumerating VPCs...")
                vpcs = self._enum_vpcs()
                if vpcs:
                    results['vpcs'] = vpcs
                    print_success(f"Found {len(vpcs)} VPCs")
                    
                    for vpc in vpcs:
                        vpc_id = vpc.get('VpcId', 'Unknown')
                        cidr = vpc.get('CidrBlock', 'Unknown')
                        state = vpc.get('State', 'Unknown')
                        is_default = vpc.get('IsDefault', False)
                        
                        print_info(f"  - {vpc_id}")
                        print_info(f"    CIDR: {cidr}, State: {state}")
                        if is_default:
                            print_info(f"    ⚠️  Default VPC")
                else:
                    print_info("No VPCs found or access denied")
            
            # Enumerate subnets
            if self.enum_subnets.value:
                print_info("\n[2] Enumerating subnets...")
                subnets = self._enum_subnets()
                if subnets:
                    results['subnets'] = subnets
                    print_success(f"Found {len(subnets)} subnets")
                    
                    for subnet in subnets[:10]:  # Show first 10
                        subnet_id = subnet.get('SubnetId', 'Unknown')
                        vpc_id = subnet.get('VpcId', 'Unknown')
                        cidr = subnet.get('CidrBlock', 'Unknown')
                        az = subnet.get('AvailabilityZone', 'Unknown')
                        public = subnet.get('MapPublicIpOnLaunch', False)
                        
                        print_info(f"  - {subnet_id} ({cidr})")
                        print_info(f"    VPC: {vpc_id}, AZ: {az}")
                        if public:
                            print_warning(f"    ⚠️  Public subnet (MapPublicIpOnLaunch)")
                    
                    if len(subnets) > 10:
                        print_info(f"  ... and {len(subnets) - 10} more")
                else:
                    print_info("No subnets found or access denied")
            
            # Enumerate route tables
            if self.enum_route_tables.value:
                print_info("\n[3] Enumerating route tables...")
                route_tables = self._enum_route_tables()
                if route_tables:
                    results['route_tables'] = route_tables
                    print_success(f"Found {len(route_tables)} route tables")
                    
                    for rt in route_tables[:10]:
                        rt_id = rt.get('RouteTableId', 'Unknown')
                        vpc_id = rt.get('VpcId', 'Unknown')
                        routes = rt.get('Routes', [])
                        
                        print_info(f"  - {rt_id} (VPC: {vpc_id})")
                        for route in routes:
                            dest = route.get('DestinationCidrBlock', 'Unknown')
                            gateway = route.get('GatewayId', route.get('NatGatewayId', 'local'))
                            print_info(f"    {dest} -> {gateway}")
                    
                    if len(route_tables) > 10:
                        print_info(f"  ... and {len(route_tables) - 10} more")
                else:
                    print_info("No route tables found or access denied")
            
            # Enumerate internet gateways
            if self.enum_internet_gateways.value:
                print_info("\n[4] Enumerating internet gateways...")
                igws = self._enum_internet_gateways()
                if igws:
                    results['internet_gateways'] = igws
                    print_success(f"Found {len(igws)} internet gateways")
                    for igw in igws:
                        print_info(f"  - {igw.get('InternetGatewayId', 'Unknown')}")
                else:
                    print_info("No internet gateways found")
            
            # Enumerate NAT gateways
            if self.enum_nat_gateways.value:
                print_info("\n[5] Enumerating NAT gateways...")
                nat_gws = self._enum_nat_gateways()
                if nat_gws:
                    results['nat_gateways'] = nat_gws
                    print_success(f"Found {len(nat_gws)} NAT gateways")
                    for nat in nat_gws:
                        nat_id = nat.get('NatGatewayId', 'Unknown')
                        public_ip = nat.get('NatGatewayAddresses', [{}])[0].get('PublicIp', 'N/A')
                        print_info(f"  - {nat_id} (Public IP: {public_ip})")
                else:
                    print_info("No NAT gateways found")
            
            # Enumerate VPC peering
            if self.enum_vpc_peering.value:
                print_info("\n[6] Enumerating VPC peering connections...")
                peerings = self._enum_vpc_peering()
                if peerings:
                    results['vpc_peering'] = peerings
                    print_success(f"Found {len(peerings)} VPC peering connections")
                    for peer in peerings:
                        peer_id = peer.get('VpcPeeringConnectionId', 'Unknown')
                        status = peer.get('Status', {}).get('Code', 'Unknown')
                        print_info(f"  - {peer_id} (Status: {status})")
                else:
                    print_info("No VPC peering connections found")
            
            # Map topology
            if self.map_topology.value and results.get('vpcs'):
                print_info("\n[7] Mapping network topology...")
                topology = self._map_topology(results)
                if topology:
                    results['topology'] = topology
                    print_success("Network topology mapped")
                    print_info("\nTopology Summary:")
                    for vpc_id, vpc_info in topology.items():
                        print_info(f"  VPC: {vpc_id}")
                        print_info(f"    Subnets: {len(vpc_info.get('subnets', []))}")
                        print_info(f"    Route Tables: {len(vpc_info.get('route_tables', []))}")
                        print_info(f"    Internet Gateways: {len(vpc_info.get('internet_gateways', []))}")
            
            # Summary
            print_info("\n" + "=" * 80)
            print_info("ENUMERATION SUMMARY")
            print_info("=" * 80)
            print_success(f"Enumerated:")
            print_info(f"  - VPCs: {len(results.get('vpcs', []))}")
            print_info(f"  - Subnets: {len(results.get('subnets', []))}")
            print_info(f"  - Route Tables: {len(results.get('route_tables', []))}")
            print_info(f"  - Internet Gateways: {len(results.get('internet_gateways', []))}")
            print_info(f"  - NAT Gateways: {len(results.get('nat_gateways', []))}")
            print_info(f"  - VPC Peering: {len(results.get('vpc_peering', []))}")
            
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
    
    def _enum_vpcs(self):
        """Enumerate VPCs"""
        cmd = "aws ec2 describe-vpcs 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('Vpcs', [])
            except:
                pass
        
        # Try Python boto3
        python_cmd = """
python3 -c "
import boto3, json
try:
    ec2 = boto3.client('ec2')
    response = ec2.describe_vpcs()
    print(json.dumps(response.get('Vpcs', [])))
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
    
    def _enum_subnets(self):
        """Enumerate subnets"""
        cmd = "aws ec2 describe-subnets 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('Subnets', [])
            except:
                pass
        
        # Try Python boto3
        python_cmd = """
python3 -c "
import boto3, json
try:
    ec2 = boto3.client('ec2')
    response = ec2.describe_subnets()
    print(json.dumps(response.get('Subnets', [])))
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
    
    def _enum_route_tables(self):
        """Enumerate route tables"""
        cmd = "aws ec2 describe-route-tables 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('RouteTables', [])
            except:
                pass
        
        # Try Python boto3
        python_cmd = """
python3 -c "
import boto3, json
try:
    ec2 = boto3.client('ec2')
    response = ec2.describe_route_tables()
    print(json.dumps(response.get('RouteTables', [])))
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
    
    def _enum_internet_gateways(self):
        """Enumerate internet gateways"""
        cmd = "aws ec2 describe-internet-gateways 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('InternetGateways', [])
            except:
                pass
        return []
    
    def _enum_nat_gateways(self):
        """Enumerate NAT gateways"""
        cmd = "aws ec2 describe-nat-gateways 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('NatGateways', [])
            except:
                pass
        return []
    
    def _enum_vpc_peering(self):
        """Enumerate VPC peering connections"""
        cmd = "aws ec2 describe-vpc-peering-connections 2>/dev/null"
        result = self.cmd_execute(cmd)
        
        if result:
            try:
                data = json.loads(result)
                return data.get('VpcPeeringConnections', [])
            except:
                pass
        return []
    
    def _map_topology(self, results):
        """Map network topology"""
        topology = {}
        
        # Group resources by VPC
        for vpc in results.get('vpcs', []):
            vpc_id = vpc.get('VpcId')
            if vpc_id:
                topology[vpc_id] = {
                    'vpc': vpc,
                    'subnets': [],
                    'route_tables': [],
                    'internet_gateways': [],
                    'nat_gateways': []
                }
        
        # Add subnets
        for subnet in results.get('subnets', []):
            vpc_id = subnet.get('VpcId')
            if vpc_id and vpc_id in topology:
                topology[vpc_id]['subnets'].append(subnet)
        
        # Add route tables
        for rt in results.get('route_tables', []):
            vpc_id = rt.get('VpcId')
            if vpc_id and vpc_id in topology:
                topology[vpc_id]['route_tables'].append(rt)
        
        # Add internet gateways
        for igw in results.get('internet_gateways', []):
            attachments = igw.get('Attachments', [])
            for att in attachments:
                vpc_id = att.get('VpcId')
                if vpc_id and vpc_id in topology:
                    topology[vpc_id]['internet_gateways'].append(igw)
        
        # Add NAT gateways
        for nat in results.get('nat_gateways', []):
            vpc_id = nat.get('VpcId')
            if vpc_id and vpc_id in topology:
                topology[vpc_id]['nat_gateways'].append(nat)
        
        return topology

