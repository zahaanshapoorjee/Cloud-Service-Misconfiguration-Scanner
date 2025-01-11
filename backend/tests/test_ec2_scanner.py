"""
Module: test_ec2_scanner
Description:
    This module contains pytest test cases for verifying the functionality of the EC2Scanner.
    It uses the moto library to mock AWS EC2 services and ensures that the scanning logic for
    security groups and network ACLs works as expected.
"""

import pytest
from moto import mock_aws
import boto3
from app.scanning.ec2_scanner import EC2Scanner

@mock_aws
def test_scan_security_groups():
    """
    Test the EC2Scanner.scan_security_groups() method to verify it correctly identifies
    security groups with overly permissive rules.

    The test sets up a mock EC2 environment in the 'us-east-1' region:
      - It creates a security group with a rule allowing SSH (port 22) access from anywhere.
      - It then initializes an EC2Scanner and verifies that exactly one finding is returned.
      - Additional assertions check that the finding contains the expected protocol, ports, and CIDR.
    """
    # Set up a mocked EC2 client in the 'us-east-1' region.
    ec2 = boto3.client('ec2', region_name='us-east-1')
    
    # Create a security group with a rule that allows SSH (port 22) from anywhere.
    sg = ec2.create_security_group(GroupName='test-sg', Description='Test SG')
    ec2.authorize_security_group_ingress(
        GroupId=sg['GroupId'],
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )
    
    # Initialize the EC2Scanner.
    scanner = EC2Scanner(region='us-east-1')
    findings = scanner.scan_security_groups()
    
    # Assert that one finding is detected.
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    # Validate that the finding details match the expected configuration.
    assert findings[0]['CidrIp'] == '0.0.0.0/0'
    assert findings[0]['IpProtocol'] == 'tcp'
    assert findings[0]['FromPort'] == 22
    assert findings[0]['ToPort'] == 22

@mock_aws
def test_scan_network_acls():
    """
    Test the EC2Scanner.scan_network_acls() method to verify it correctly identifies
    misconfigured network ACL entries that allow all traffic.

    The test sets up a mock EC2 environment in the 'us-east-1' region:
      - A VPC is created.
      - A Network ACL is created for that VPC.
      - Two ACL entries are added: one ingress and one egress, both allowing all traffic from/to anywhere.
      - The scanner is then initialized and is expected to return two findings corresponding to the two rules.
      - The test further asserts that each finding includes the expected attributes.
    """
    # Set up a mocked EC2 client in the 'us-east-1' region.
    ec2 = boto3.client('ec2', region_name='us-east-1')
    
    # Create a VPC.
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
    
    # Create a Network ACL for the created VPC.
    acl = ec2.create_network_acl(VpcId=vpc['Vpc']['VpcId'])
    
    # Create an ingress rule that allows all traffic from anywhere.
    ec2.create_network_acl_entry(
        NetworkAclId=acl['NetworkAcl']['NetworkAclId'],
        RuleNumber=100,
        Protocol='-1',  # '-1' indicates all protocols.
        RuleAction='allow',
        Egress=False,
        CidrBlock='0.0.0.0/0'
    )
    
    # Create an egress rule that allows all traffic to anywhere.
    ec2.create_network_acl_entry(
        NetworkAclId=acl['NetworkAcl']['NetworkAclId'],
        RuleNumber=100,
        Protocol='-1',
        RuleAction='allow',
        Egress=True,
        CidrBlock='0.0.0.0/0'
    )
    
    # Initialize the EC2Scanner.
    scanner = EC2Scanner(region='us-east-1')
    findings = scanner.scan_network_acls()
    
    # Filter findings to only include those for the ACL created in this test.
    test_acl_findings = [f for f in findings if f['NetworkAclId'] == acl['NetworkAcl']['NetworkAclId']]
    
    # Assert that there are exactly 2 findings (one for ingress, one for egress).
    assert len(test_acl_findings) == 2, f"Expected 2 findings for test ACL, got {len(test_acl_findings)}"
    
    # Validate that each finding reports the expected CIDR, rule action, and protocol.
    for finding in test_acl_findings:
        assert finding['CidrBlock'] == '0.0.0.0/0', f"Expected CidrBlock '0.0.0.0/0', got {finding['CidrBlock']}"
        assert finding['RuleAction'] == 'allow', f"Expected RuleAction 'allow', got {finding['RuleAction']}"
        assert finding['Protocol'] == '-1', f"Expected Protocol '-1', got {finding['Protocol']}"
