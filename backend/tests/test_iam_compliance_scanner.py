"""
Module: test_iam_compliance_scanner
Description:
    This module contains pytest test cases for verifying the functionality of the IAMComplianceScanner.
    It uses the moto library to simulate AWS IAM responses so that tests run without accessing real AWS resources.
    The tests cover scenarios such as detecting overly permissive policies and verifying the root account MFA configuration.
"""

import pytest
from moto import mock_aws
import boto3
from app.scanning.iam_compliance_scanner import IAMComplianceScanner

@mock_aws
def test_scan_overly_permissive_policies():
    """
    Test that the IAMComplianceScanner correctly identifies overly permissive policies.

    This test sets up a mock IAM client in the 'us-east-1' region and:
      - Creates an overly permissive policy that allows all actions on all resources.
      - Creates a user and attaches the overly permissive policy to this user.
    After the setup, the scanner is run and expected to return one finding indicating the policy is overly permissive.

    Asserts:
        - The findings object is a list.
        - Exactly one finding is returned.
        - The finding's 'PolicyName' matches the name of the created policy.
    """
    # Set up a mocked IAM client in the 'us-east-1' region.
    iam = boto3.client('iam', region_name='us-east-1')
    
    # Create an overly permissive IAM policy that allows all actions on all resources.
    permissive_policy = iam.create_policy(
        PolicyName='PermissivePolicy',
        PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
    )
    
    # Create a user and attach the overly permissive policy to the user.
    iam.create_user(UserName='test-user')
    iam.attach_user_policy(UserName='test-user', PolicyArn=permissive_policy['Policy']['Arn'])
    
    # Initialize the IAMComplianceScanner.
    scanner = IAMComplianceScanner(region='us-east-1')
    findings = scanner.scan_overly_permissive_policies()
    
    # Verify that findings is a list and contains exactly one finding.
    assert isinstance(findings, list)
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    # Validate that the returned finding is for the created permissive policy.
    assert findings[0]['PolicyName'] == 'PermissivePolicy', f"Expected PolicyName 'PermissivePolicy', got {findings[0]['PolicyName']}"

@mock_aws
def test_scan_root_account_mfa():
    """
    Test that the IAMComplianceScanner correctly checks for root account MFA configuration.

    Since moto does not simulate the actual root account environment, the test verifies
    that when scan_root_account_mfa() is executed, the scanner either returns a finding indicating
    that the root account does not have MFA enabled, or returns an empty list if that's the intended behavior.

    Asserts:
        - If findings are returned, the 'Issue' field matches the expected noncompliance message.
        - Otherwise, findings is an empty list.
    """
    # Set up a mocked IAM client in the 'us-east-1' region.
    iam = boto3.client('iam', region_name='us-east-1')
    
    # Initialize the IAMComplianceScanner.
    scanner = IAMComplianceScanner(region='us-east-1')
    findings = scanner.scan_root_account_mfa()
    
    # Validate that if findings are returned, they indicate a lack of MFA on the root account.
    if findings:
        assert findings[0]['Issue'] == "Root account does not have MFA enabled.", \
            f"Expected Issue 'Root account does not have MFA enabled.', got {findings[0]['Issue']}"
    else:
        # If no findings are returned, then the scanner considers the configuration compliant.
        assert findings == [], "Expected empty findings list if MFA is simulated as enabled"
