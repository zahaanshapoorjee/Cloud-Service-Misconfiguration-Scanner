"""
Module: test_rds_scanner
Description:
    This module contains pytest test cases for verifying the functionality of the RDSScanner.
    It uses the moto library to mock AWS RDS responses so that tests are run in isolation
    without interacting with real AWS resources.

    The tests cover:
      - Detection of unencrypted RDS instances.
      - Identification of publicly accessible RDS instances.
      - Detection of insecure RDS parameter groups where SSL is not enforced.
"""

import pytest
from moto import mock_aws
import boto3
from app.scanning.rds_scanner import RDSScanner

@mock_aws
def test_scan_unencrypted_databases():
    """
    Test that the RDSScanner.scan_unencrypted_databases() method correctly identifies
    unencrypted RDS instances.

    The test sets up a mocked RDS environment in the 'us-east-1' region by creating:
      - An unencrypted RDS instance (StorageEncrypted set to False).
      - An encrypted RDS instance (StorageEncrypted set to True).

    The scanner is then expected to return only one finding corresponding to the unencrypted instance.

    Asserts:
        - Findings is a list.
        - Exactly one finding is returned.
        - The finding's DBInstanceIdentifier matches 'unencrypted-db'.
        - The finding indicates that StorageEncrypted is False.
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
        DBInstanceClass='db.t2.micro'  # Required parameter for instance class.
    )
    
    # Create an encrypted RDS instance.
    rds.create_db_instance(
        DBInstanceIdentifier='encrypted-db',
        Engine='mysql',
        MasterUsername='admin',
        MasterUserPassword='password',
        AllocatedStorage=20,
        StorageEncrypted=True,
        DBInstanceClass='db.t2.micro'  # Required parameter for instance class.
    )
    
    # Initialize the RDSScanner.
    scanner = RDSScanner(region='us-east-1')
    findings = scanner.scan_unencrypted_databases()
    
    # Perform assertions.
    assert isinstance(findings, list), "Findings should be a list"
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    # Check that the finding corresponds to the unencrypted database.
    assert findings[0]['DBInstanceIdentifier'] == 'unencrypted-db'
    assert findings[0]['StorageEncrypted'] == False

@mock_aws
def test_scan_public_accessible_databases():
    """
    Test that the RDSScanner.scan_public_accessible_databases() method correctly identifies
    publicly accessible RDS instances.

    The test creates two RDS instances:
      - One instance with PubliclyAccessible set to True.
      - One instance with PubliclyAccessible set to False.

    The scanner should return a finding only for the publicly accessible instance.

    Asserts:
        - Findings is a list.
        - Exactly one finding is returned.
        - The finding corresponds to the DBInstanceIdentifier 'public-db'.
        - The finding indicates that PubliclyAccessible is True.
    """
    # Set up a mocked RDS client.
    rds = boto3.client('rds', region_name='us-east-1')
    
    # Create a publicly accessible RDS instance.
    rds.create_db_instance(
        DBInstanceIdentifier='public-db',
        Engine='mysql',
        MasterUsername='admin',
        MasterUserPassword='password',
        AllocatedStorage=20,
        PubliclyAccessible=True,
        DBInstanceClass='db.t2.micro'  # Required parameter for instance class.
    )
    
    # Create a privately accessible RDS instance.
    rds.create_db_instance(
        DBInstanceIdentifier='private-db',
        Engine='mysql',
        MasterUsername='admin',
        MasterUserPassword='password',
        AllocatedStorage=20,
        PubliclyAccessible=False,
        DBInstanceClass='db.t2.micro'  # Required parameter for instance class.
    )
    
    # Initialize the RDSScanner.
    scanner = RDSScanner(region='us-east-1')
    findings = scanner.scan_public_accessible_databases()
    
    # Perform assertions.
    assert isinstance(findings, list), "Findings should be a list"
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0]['DBInstanceIdentifier'] == 'public-db'
    assert findings[0]['PubliclyAccessible'] == True

@mock_aws
def test_scan_db_parameter_groups():
    """
    Test that the RDSScanner.scan_db_parameter_groups() method correctly identifies RDS parameter groups
    with insecure configurations.

    The test sets up a mocked RDS environment where:
      - An insecure parameter group is created with 'rds.force_ssl' set to '0'.
      - A secure parameter group is created with 'rds.force_ssl' set to '1' (control).

    The scanner should only flag the insecure parameter group.

    Asserts:
        - Findings is a list.
        - Exactly one finding is returned.
        - The finding corresponds to the parameter group named 'insecure-pg'.
        - The finding's parameter 'rds.force_ssl' has a value of '0'.
    """
    # Set up a mocked RDS client.
    rds = boto3.client('rds', region_name='us-east-1')
    
    # Create an insecure parameter group and modify it to set 'rds.force_ssl' to '0'.
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
    
    # Create a secure parameter group (control) with 'rds.force_ssl' set to '1'.
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
    
    # Initialize the RDSScanner.
    scanner = RDSScanner(region='us-east-1')
    findings = scanner.scan_db_parameter_groups()
    
    # Perform assertions.
    assert isinstance(findings, list), "Findings should be a list"
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0]['DBParameterGroupName'] == 'insecure-pg'
    assert findings[0]['ParameterName'] == 'rds.force_ssl'
    assert findings[0]['CurrentValue'] == '0'
