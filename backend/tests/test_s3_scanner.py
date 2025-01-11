"""
Module: test_s3_scanner
Description:
    This module contains pytest test cases for verifying the functionality of the S3Scanner.
    It uses the moto library to simulate AWS S3 responses so that tests run in isolation
    without interacting with real AWS resources. In this test, we focus on detecting
    buckets with public access via their ACL settings.
"""

import pytest
from moto import mock_aws
import boto3
from app.scanning.s3_scanner import S3Scanner

@mock_aws
def test_scan_buckets_public_access():
    """
    Test that S3Scanner.scan_buckets_public_access() correctly detects buckets with public access.

    Setup:
      - Create a bucket 'public-bucket' with its ACL set to 'public-read'.
      - Create a bucket 'private-bucket' with its ACL set to 'private'.
      
    Expected:
      - The scanner should detect at least one finding corresponding to 'public-bucket'.
      - At least one of the findings for 'public-bucket' should report the permission as 'READ'.
    
    Note:
      Due to multiple checks (such as ACL and public access block configuration),
      the scanner may return additional findings. Therefore, the assertions check for the
      presence of 'public-bucket' in the findings rather than enforcing an exact count.
    """
    # Set up a mocked S3 client in the 'us-east-1' region.
    s3 = boto3.client('s3', region_name='us-east-1')
    
    # Create a bucket named 'public-bucket' and configure its ACL to 'public-read'.
    s3.create_bucket(Bucket='public-bucket')
    s3.put_bucket_acl(
        Bucket='public-bucket',
        ACL='public-read'
    )
    
    # Create another bucket named 'private-bucket' and configure its ACL to 'private'.
    s3.create_bucket(Bucket='private-bucket')
    s3.put_bucket_acl(
        Bucket='private-bucket',
        ACL='private'
    )
    
    # Initialize the S3Scanner.
    scanner = S3Scanner(region='us-east-1')
    findings = scanner.scan_buckets_public_access()
    
    # Instead of expecting exactly one finding, verify that at least one finding for 'public-bucket' exists.
    public_bucket_findings = [f for f in findings if f.get('BucketName') == 'public-bucket']
    assert len(public_bucket_findings) >= 1, (
        f"Expected at least 1 finding for 'public-bucket', got {len(public_bucket_findings)}"
    )
    
    # Verify that among the findings for 'public-bucket', at least one reports the Permission as 'READ'.
    assert any(f.get('Permission') == 'READ' for f in public_bucket_findings), (
        "Expected at least one finding with Permission 'READ' for 'public-bucket'"
    )
