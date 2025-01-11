"""
Module: test_rds_compliance_scanner
Description:
    This module contains pytest test cases for verifying the functionality of the
    RDSComplianceScanner. It uses the moto library to mock AWS RDS responses so that tests
    run without impacting real AWS resources.
    
    The tests verify that:
      - Unencrypted RDS instances are correctly identified.
      - Publicly accessible RDS instances are flagged.
      - RDS parameter groups with insecure settings (i.e., rds.force_ssl not set to '1') are detected.
"""

import pytest
from moto import mock_aws
import boto3
from app.scanning.rds_compliance_scanner import RDSComplianceScanner

@mock_aws
def test_scan_unencrypted_instances():
    """
    Test that the RDSComplianceScanner.scan_unencrypted_instances() method correctly identifies unencrypted RDS instances.

    In the mock environment, two RDS instances are created:
      - One unencrypted instance (StorageEncrypted set to False).
      - One encrypted instance (StorageEncrypted set to True).
    
    The scanner is expected to flag only the unencrypted instance.

    Asserts:
        - Findings is a list.
        - Exactly one finding is returned.
        - The finding corresponds to the unencrypted instance identified by its DBInstanceIdentifier.
    """
    # Set up a mocked RDS client in the 'us-east-1' region.
    rds = boto3.client('rds', region_name='us-east-1')
    
    # Create an unencrypted RDS instance.
    rds.create_db_instance(
        DBInstanceIdentifier='unencrypted-db',
        Engine='mysql',
        MasterUsername='admin',
        MasterUserPassword='password',
        AllocatedStorage=20,
        StorageEncrypted=False,
        DBInstanceClass='db.t2.micro'
    )
    
    # Create an encrypted RDS instance.
    rds.create_db_instance(
        DBInstanceIdentifier='encrypted-db',
        Engine='mysql',
        MasterUsername='admin',
        MasterUserPassword='password',
        AllocatedStorage=20,
        StorageEncrypted=True,
        DBInstanceClass='db.t2.micro'
    )
    
    # Initialize the RDSComplianceScanner.
    scanner = RDSComplianceScanner(region='us-east-1')
    findings = scanner.scan_unencrypted_instances()
    
    # Assert that findings is a list containing one finding corresponding to the unencrypted instance.
    assert isinstance(findings, list)
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0]['DBInstanceIdentifier'] == 'unencrypted-db'

@mock_aws
def test_scan_public_instances():
    """
    Test that the RDSComplianceScanner.scan_public_instances() method correctly identifies publicly accessible RDS instances.

    In the mock environment, two RDS instances are created:
      - One publicly accessible instance (PubliclyAccessible set to True).
      - One privately accessible instance (PubliclyAccessible set to False).
    
    The scanner should flag only the publicly accessible instance.

    Asserts:
        - Findings is a list.
        - Exactly one finding is returned.
        - The finding corresponds to the publicly accessible instance identified by its DBInstanceIdentifier.
    """
    # Set up a mocked RDS client in the 'us-east-1' region.
    rds = boto3.client('rds', region_name='us-east-1')
    
    # Create a publicly accessible RDS instance.
    rds.create_db_instance(
        DBInstanceIdentifier='public-db',
        Engine='mysql',
        MasterUsername='admin',
        MasterUserPassword='password',
        AllocatedStorage=20,
        PubliclyAccessible=True,
        DBInstanceClass='db.t2.micro'
    )
    
    # Create a privately accessible RDS instance.
    rds.create_db_instance(
        DBInstanceIdentifier='private-db',
        Engine='mysql',
        MasterUsername='admin',
        MasterUserPassword='password',
        AllocatedStorage=20,
        PubliclyAccessible=False,
        DBInstanceClass='db.t2.micro'
    )
    
    # Initialize the RDSComplianceScanner.
    scanner = RDSComplianceScanner(region='us-east-1')
    findings = scanner.scan_public_instances()
    
    # Assert that findings is a list containing one finding corresponding to the public instance.
    assert isinstance(findings, list)
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0]['DBInstanceIdentifier'] == 'public-db'

@mock_aws
def test_scan_db_parameter_groups():
    """
    Test that the RDSComplianceScanner.scan_db_parameter_groups() method correctly identifies RDS parameter groups
    with insecure settings (i.e., rds.force_ssl not set to '1').

    In the mock environment:
      - An insecure parameter group is created with rds.force_ssl set to '0'.
      - A secure parameter group is created with rds.force_ssl set to '1'.
      
    The scanner should flag only the insecure parameter group.

    Asserts:
        - Findings is a list.
        - Exactly one finding is returned.
        - The finding corresponds to the insecure parameter group identified by its DBParameterGroupName.
    """
    # Set up a mocked RDS client in the 'us-east-1' region.
    rds = boto3.client('rds', region_name='us-east-1')
    
    # Create a parameter group with an insecure setting (rds.force_ssl set to '0').
    rds.create_db_parameter_group(
        DBParameterGroupName='insecure-pg',
        DBParameterGroupFamily='mysql8.0',
        Description='Insecure Parameter Group'
    )
    rds.modify_db_parameter_group(
        DBParameterGroupName='insecure-pg',
        Parameters=[
            {
                'ParameterName': 'rds.force_ssl',
                'ParameterValue': '0',
                'ApplyMethod': 'immediate'
            }
        ]
    )
    
    # Create a secure parameter group for control (rds.force_ssl set to '1').
    rds.create_db_parameter_group(
        DBParameterGroupName='secure-pg',
        DBParameterGroupFamily='mysql8.0',
        Description='Secure Parameter Group'
    )
    rds.modify_db_parameter_group(
        DBParameterGroupName='secure-pg',
        Parameters=[
            {
                'ParameterName': 'rds.force_ssl',
                'ParameterValue': '1',
                'ApplyMethod': 'immediate'
            }
        ]
    )
    
    # Initialize the RDSComplianceScanner.
    scanner = RDSComplianceScanner(region='us-east-1')
    findings = scanner.scan_db_parameter_groups()
    
    # Assert that findings is a list containing one finding corresponding to the insecure parameter group.
    assert isinstance(findings, list)
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0]['DBParameterGroupName'] == 'insecure-pg'
