"""
Module: test_s3_compliance_scanner
Description:
    This module contains pytest test cases for verifying the functionality of the S3ComplianceScanner.
    It uses the moto library to mock AWS S3 service responses so that tests are run without
    interacting with real AWS resources. The tests verify that the scanner correctly identifies:
      - Public access issues via ACLs, bucket policies, and public access block configurations.
      - Buckets without logging enabled.
      - Buckets without encryption enforced.
      - Buckets with versioning disabled.
      - Overly permissive bucket policies that do not meet PCI requirements.
"""

import json
import pytest
from moto import mock_aws
import boto3
from botocore.exceptions import ClientError
from app.scanning.s3_compliance_scanner import S3ComplianceScanner

@mock_aws
def test_scan_s3_public_access():
    """
    Test that the S3ComplianceScanner.scan_s3_public_access() method identifies buckets
    that allow public access via ACLs and bucket policies, as well as issues with Public Access Block.

    Setup:
      - Creates a bucket ('public-bucket') with its ACL set to public-read.
      - Creates a second bucket ('policy-public-bucket') with an overly permissive bucket policy
        that allows public access via a wildcard Principal.

    Asserts:
      - The resulting findings is a list with at least two entries (one for each bucket).
      - Both bucket names ('public-bucket' and 'policy-public-bucket') are included in the findings.
    """
    # Set up the mocked S3 client in the 'us-east-1' region.
    s3 = boto3.client('s3', region_name='us-east-1')

    # Create a bucket and set its ACL to public-read to simulate public accessibility.
    s3.create_bucket(Bucket='public-bucket')
    s3.put_bucket_acl(Bucket='public-bucket', ACL='public-read')
    
    # Create another bucket and attach a bucket policy that allows public access.
    s3.create_bucket(Bucket='policy-public-bucket')
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::policy-public-bucket/*"
            }
        ]
    }
    s3.put_bucket_policy(Bucket='policy-public-bucket', Policy=json.dumps(policy))
    
    # Initialize the S3ComplianceScanner.
    scanner = S3ComplianceScanner(region='us-east-1')
    findings = scanner.scan_s3_public_access()
    
    # Assertions: Verify that findings is a list containing at least two entries.
    assert isinstance(findings, list)
    assert len(findings) >= 2, f"Expected at least 2 findings, got {len(findings)}"
    
    # Verify that the names of both buckets are included in the findings.
    bucket_names = [f['BucketName'] for f in findings]
    assert 'public-bucket' in bucket_names, f"'public-bucket' not found in {bucket_names}"
    assert 'policy-public-bucket' in bucket_names, f"'policy-public-bucket' not found in {bucket_names}"


@mock_aws
def test_scan_s3_logging_enabled():
    """
    Test that the S3ComplianceScanner.scan_s3_logging_enabled() method correctly identifies buckets without logging enabled.

    Setup:
      - Creates a bucket 'no-logging-bucket' with no logging configuration.
      - Creates a target bucket 'log-target' intended for log delivery and applies a canned ACL (log-delivery-write).
      - Creates a bucket 'logging-bucket' with logging enabled, directing logs to 'log-target'.

    Asserts:
      - Findings is a list.
      - 'no-logging-bucket' is flagged as missing logging.
      - 'logging-bucket' is not flagged.
    """
    # Set up the mocked S3 client.
    s3 = boto3.client('s3', region_name='us-east-1')
    
    # Create a bucket without logging enabled.
    s3.create_bucket(Bucket='no-logging-bucket')
    
    # Create a target bucket to receive logs and configure its ACL for log delivery.
    s3.create_bucket(Bucket='log-target')
    s3.put_bucket_acl(Bucket='log-target', ACL='log-delivery-write')
    
    # Create a bucket with logging enabled, configured to send logs to 'log-target'.
    s3.create_bucket(Bucket='logging-bucket')
    s3.put_bucket_logging(
        Bucket='logging-bucket',
        BucketLoggingStatus={
            'LoggingEnabled': {
                'TargetBucket': 'log-target',
                'TargetPrefix': 'logs/'
            }
        }
    )
    
    # Initialize the S3ComplianceScanner.
    scanner = S3ComplianceScanner(region='us-east-1')
    findings = scanner.scan_s3_logging_enabled()
    
    # Assertions: Ensure that 'no-logging-bucket' is flagged and 'logging-bucket' is not.
    assert isinstance(findings, list)
    bucket_names = [f['BucketName'] for f in findings]
    assert 'no-logging-bucket' in bucket_names, f"Expected 'no-logging-bucket' to be flagged, got {bucket_names}"
    assert 'logging-bucket' not in bucket_names, f"'logging-bucket' should not be flagged."


@mock_aws
def test_scan_s3_encryption_enabled():
    """
    Test that the S3ComplianceScanner.scan_s3_encryption_enabled() method correctly identifies buckets lacking encryption.

    Setup:
      - Creates a bucket 'unencrypted-bucket' without any server-side encryption configuration.
      - Creates a bucket 'encrypted-bucket' and applies server-side encryption using AES256.

    Asserts:
      - Findings is a list.
      - 'unencrypted-bucket' is flagged as lacking encryption.
      - 'encrypted-bucket' is not flagged.
    """
    # Set up the mocked S3 client.
    s3 = boto3.client('s3', region_name='us-east-1')
    
    # Create a bucket with no encryption enabled.
    s3.create_bucket(Bucket='unencrypted-bucket')
    
    # Create a bucket and enable server-side encryption using AES256.
    s3.create_bucket(Bucket='encrypted-bucket')
    s3.put_bucket_encryption(
        Bucket='encrypted-bucket',
        ServerSideEncryptionConfiguration={
            'Rules': [
                {
                    'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}
                }
            ]
        }
    )
    
    # Initialize the S3ComplianceScanner.
    scanner = S3ComplianceScanner(region='us-east-1')
    findings = scanner.scan_s3_encryption_enabled()
    
    # Assertions: Verify that 'unencrypted-bucket' is flagged and 'encrypted-bucket' is not.
    assert isinstance(findings, list)
    bucket_names = [f['BucketName'] for f in findings]
    assert 'unencrypted-bucket' in bucket_names, f"'unencrypted-bucket' should be flagged, got {bucket_names}"
    assert 'encrypted-bucket' not in bucket_names, f"'encrypted-bucket' should not be flagged."


@mock_aws
def test_scan_s3_versioning_enabled():
    """
    Test that the S3ComplianceScanner.scan_s3_versioning_enabled() method correctly identifies buckets without versioning enabled.

    Setup:
      - Creates a bucket 'no-versioning-bucket' without versioning enabled.
      - Creates a bucket 'versioning-bucket' and enables versioning.

    Asserts:
      - Findings is a list.
      - 'no-versioning-bucket' is flagged.
      - 'versioning-bucket' is not flagged.
    """
    # Set up the mocked S3 client.
    s3 = boto3.client('s3', region_name='us-east-1')
    
    # Create a bucket without versioning enabled.
    s3.create_bucket(Bucket='no-versioning-bucket')
    
    # Create a bucket with versioning enabled.
    s3.create_bucket(Bucket='versioning-bucket')
    s3.put_bucket_versioning(
        Bucket='versioning-bucket',
        VersioningConfiguration={'Status': 'Enabled'}
    )
    
    # Initialize the S3ComplianceScanner.
    scanner = S3ComplianceScanner(region='us-east-1')
    findings = scanner.scan_s3_versioning_enabled()
    
    # Assertions: Verify that 'no-versioning-bucket' is flagged and 'versioning-bucket' is not.
    assert isinstance(findings, list)
    bucket_names = [f['BucketName'] for f in findings]
    assert 'no-versioning-bucket' in bucket_names, f"Expected 'no-versioning-bucket' to be flagged, got {bucket_names}"
    assert 'versioning-bucket' not in bucket_names, f"'versioning-bucket' should not be flagged."


@mock_aws
def test_scan_s3_policy_restrictions():
    """
    Test that the S3ComplianceScanner.scan_s3_policy_restrictions() method correctly identifies overly permissive bucket policies.

    Setup:
      - Creates a bucket 'policy-restricted-bucket' with a bucket policy that grants public access (Principal "*" ) for all actions.
      - Creates a bucket 'policy-restricted-ok-bucket' with a restrictive bucket policy that limits access to a specific user (control).

    Asserts:
      - Findings is a list.
      - 'policy-restricted-bucket' is flagged.
      - 'policy-restricted-ok-bucket' is not flagged.
    """
    # Set up the mocked S3 client.
    s3 = boto3.client('s3', region_name='us-east-1')
    
    # Create a bucket with an overly permissive bucket policy.
    s3.create_bucket(Bucket='policy-restricted-bucket')
    overly_permissive_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::policy-restricted-bucket/*"
            }
        ]
    }
    s3.put_bucket_policy(Bucket='policy-restricted-bucket', Policy=json.dumps(overly_permissive_policy))
    
    # Create a bucket with a more restrictive bucket policy (control).
    s3.create_bucket(Bucket='policy-restricted-ok-bucket')
    restrictive_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:user/SpecificUser"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::policy-restricted-ok-bucket/*"
            }
        ]
    }
    s3.put_bucket_policy(Bucket='policy-restricted-ok-bucket', Policy=json.dumps(restrictive_policy))
    
    # Initialize the S3ComplianceScanner.
    scanner = S3ComplianceScanner(region='us-east-1')
    findings = scanner.scan_s3_policy_restrictions()
    
    # Assertions: Ensure that findings only flag the overly permissive bucket.
    assert isinstance(findings, list)
    bucket_names = [f['BucketName'] for f in findings]
    assert 'policy-restricted-bucket' in bucket_names, (
        f"Expected 'policy-restricted-bucket' to be flagged, got {bucket_names}"
    )
    assert 'policy-restricted-ok-bucket' not in bucket_names, (
        f"'policy-restricted-ok-bucket' should not be flagged, got {bucket_names}"
    )
