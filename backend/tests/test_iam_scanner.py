"""
Module: test_iam_scanner
Description:
    This module contains pytest test cases for the IAMScanner class.
    It uses moto to mock AWS IAM so that tests run without affecting real AWS resources.
    The tests cover:
      - Detection of overly permissive policies.
      - Identification of unused access keys.
      - Verification of root account MFA status.
"""

import pytest
from moto import mock_aws
import boto3
from app.scanning.iam_scanner import IAMScanner
import datetime

@mock_aws
def test_scan_overly_permissive_policies():
    """
    Test that the IAMScanner.scan_overly_permissive_policies() method correctly
    identifies overly permissive policies.

    This test sets up a mocked IAM environment in the 'us-east-1' region:
      - Creates an overly permissive policy (allows all actions on all resources).
      - Creates a restrictive policy (only allows describing EC2 resources).
      - Attaches both policies to a single user.
    The scanner is expected to flag only the overly permissive policy.

    Asserts:
        - Exactly one finding is returned.
        - The finding corresponds to the permissive policy with the expected PolicyName.
    """
    # Set up a mocked IAM client.
    iam = boto3.client('iam', region_name='us-east-1')
    
    # Create an overly permissive IAM policy (allows all actions on all resources).
    permissive_policy = iam.create_policy(
        PolicyName='PermissivePolicy',
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    )
    
    # Create a restrictive IAM policy (allows only specific actions).
    restrictive_policy = iam.create_policy(
        PolicyName='RestrictivePolicy',
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}'
    )
    
    # Create a user and attach both policies.
    iam.create_user(UserName='test-user')
    iam.attach_user_policy(UserName='test-user', PolicyArn=permissive_policy['Policy']['Arn'])
    iam.attach_user_policy(UserName='test-user', PolicyArn=restrictive_policy['Policy']['Arn'])
    
    # Initialize the IAMScanner.
    scanner = IAMScanner(region='us-east-1')
    findings = scanner.scan_overly_permissive_policies()
    
    # Expect only the overly permissive policy to be flagged.
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0]['PolicyName'] == 'PermissivePolicy', (
        f"Expected PolicyName 'PermissivePolicy', got {findings[0]['PolicyName']}"
    )

@mock_aws
def test_scan_unused_access_keys():
    """
    Test that the IAMScanner.scan_unused_access_keys() method correctly identifies unused access keys.

    This test sets up a mocked IAM environment:
      - Creates two users: one with an active key and one with an unused key.
      - Simulates activity on the key for 'active-user' by calling an IAM action.
      - The scanner should flag the access key for 'unused-user' with a LastUsedDate of "Never Used".

    Asserts:
        - Exactly one finding is returned.
        - The returned finding corresponds to the user 'unused-user' and its key.
    """
    # Set up a mocked IAM client.
    iam = boto3.client('iam', region_name='us-east-1')
    
    # Create two users.
    iam.create_user(UserName='active-user')
    iam.create_user(UserName='unused-user')
    
    # Create access keys for both users.
    active_key = iam.create_access_key(UserName='active-user')['AccessKey']
    unused_key = iam.create_access_key(UserName='unused-user')['AccessKey']
    
    # Simulate usage for 'active-user' by calling an IAM action.
    session = boto3.Session(
        aws_access_key_id=active_key['AccessKeyId'],
        aws_secret_access_key=active_key['SecretAccessKey'],
        aws_session_token=active_key.get('SessionToken'),
        region_name='us-east-1'
    )
    iam_active = session.client('iam')
    iam_active.list_policies()  # This simulates the key being used.
    
    # Initialize the IAMScanner.
    scanner = IAMScanner(region='us-east-1')
    findings = scanner.scan_unused_access_keys()
    
    # Only the 'unused-user' key should be flagged.
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0]['UserName'] == 'unused-user'
    assert findings[0]['AccessKeyId'] == unused_key['AccessKeyId']
    assert findings[0]['LastUsedDate'] == "Never Used"

@mock_aws
def test_scan_root_account_mfa():
    """
    Test that the IAMScanner.scan_root_account_mfa() method correctly reports the MFA status for the root account.

    Note: Moto does not simulate the root account MFA settings. This test assumes that MFA is not enabled.
    The expected result is a finding indicating that the root account does not have MFA enabled.

    Asserts:
        - The returned finding indicates that MFA is disabled for the root account.
    """
    # Set up a mocked IAM client.
    iam = boto3.client('iam', region_name='us-east-1')
    
    # Initialize the IAMScanner.
    scanner = IAMScanner(region='us-east-1')
    root_mfa = scanner.scan_root_account_mfa()
    
    # Verify that the finding indicates MFA is disabled.
    assert root_mfa['RootAccountMFAEnabled'] == False, (
        "Root account MFA should be disabled (Moto does not simulate it)."
    )
