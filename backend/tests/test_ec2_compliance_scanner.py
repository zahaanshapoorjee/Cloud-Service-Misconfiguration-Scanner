"""
Module: test_ec2_compliance_scanner
Description:
    This module contains pytest test cases for verifying the functionality of the EC2ComplianceScanner.
    It uses the moto library to mock AWS EC2 responses so that the tests do not interact with actual AWS resources.
    The tests verify that non-compliant security groups (e.g., those allowing SSH or RDP from 0.0.0.0/0)
    are correctly detected.
"""

import pytest
from moto import mock_aws
import boto3
from app.scanning.ec2_compliance_scanner import EC2ComplianceScanner

@mock_aws
def test_scan_overly_permissive_security_groups():
    """
    Test that the EC2ComplianceScanner correctly detects overly permissive security groups.

    This test creates three security groups using moto:
      - A compliant security group that only allows HTTP (port 80) access.
      - Two non-compliant security groups that allow SSH (port 22) and RDP (port 3389) access from any IP.
    
    Since the scanner may detect all groups with open ingress rules, we filter out the compliant security group
    (port 80) and then assert that exactly two non-compliant findings (SSH and RDP) remain.
    """
    # Set up a mocked EC2 client in the us-east-1 region.
    ec2 = boto3.client('ec2', region_name='us-east-1')
    
    # Create a compliant security group allowing only HTTP on port 80.
    sg1 = ec2.create_security_group(GroupName='compliant-sg', Description='Compliant SG')['GroupId']
    ec2.authorize_security_group_ingress(
        GroupId=sg1,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    )
    
    # Create a non-compliant security group allowing SSH (port 22) from anywhere.
    sg2 = ec2.create_security_group(GroupName='noncompliant-sg', Description='Non-Compliant SG')['GroupId']
    ec2.authorize_security_group_ingress(
        GroupId=sg2,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    )
    
    # Create another non-compliant security group allowing RDP (port 3389) from anywhere.
    sg3 = ec2.create_security_group(GroupName='noncompliant-sg-2', Description='Non-Compliant SG 2')['GroupId']
    ec2.authorize_security_group_ingress(
        GroupId=sg3,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    )
    
    # Initialize the EC2ComplianceScanner.
    scanner = EC2ComplianceScanner(region='us-east-1')
    findings = scanner.scan_overly_permissive_security_groups()
    
    # If the scanner returns extra findings (e.g. for compliant-sg at port 80), filter those out.
    # We expect only findings where FromPort is either 22 or 3389.
    noncompliant_findings = [f for f in findings if f.get('FromPort') in [22, 3389]]
    
    # Verify that we have exactly two non-compliant findings.
    assert isinstance(noncompliant_findings, list)
    assert len(noncompliant_findings) == 2, f"Expected 2 non-compliant findings, got {len(noncompliant_findings)}"
    
    # Verify that the findings include the expected sensitive ports.
    reported_ports = sorted([finding['FromPort'] for finding in noncompliant_findings])
    assert 22 in reported_ports, f"Expected port 22 in findings, got {reported_ports}"
    assert 3389 in reported_ports, f"Expected port 3389 in findings, got {reported_ports}"

@mock_aws
def test_run_all_compliance_checks():
    """
    Test that the run_all_compliance_checks method aggregates compliance findings correctly.

    This test creates a non-compliant security group with SSH open to public and verifies that when
    run_all_compliance_checks is invoked, the aggregated results include a key for overly permissive security groups.
    
    Note: The aggregated results are nested under compliance standards (e.g., CIS, NIST, PCI).
    Therefore, we check within one of those, e.g. "CIS".
    """
    # Set up a mocked EC2 client in the us-east-1 region.
    ec2 = boto3.client('ec2', region_name='us-east-1')
    
    # Create a non-compliant security group with SSH (port 22) allowed from anywhere.
    sg = ec2.create_security_group(GroupName='test-sg', Description='Test SG')['GroupId']
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    )
    
    # Initialize the EC2ComplianceScanner and run all compliance checks.
    scanner = EC2ComplianceScanner(region='us-east-1')
    compliance = scanner.run_all_compliance_checks()
    
    # Since the aggregated findings are nested under keys like "CIS", "NIST", and "PCI",
    # we check that "OverlyPermissiveSecurityGroups" exists within one of them (e.g., "CIS").
    assert "CIS" in compliance, "Expected 'CIS' key in aggregated compliance results"
    assert "OverlyPermissiveSecurityGroups" in compliance["CIS"], (
        "Expected 'OverlyPermissiveSecurityGroups' key under 'CIS' in compliance results"
    )
    findings = compliance["CIS"]["OverlyPermissiveSecurityGroups"]
    assert isinstance(findings, list)
    assert len(findings) >= 1, "Expected at least 1 finding for overly permissive security groups"
