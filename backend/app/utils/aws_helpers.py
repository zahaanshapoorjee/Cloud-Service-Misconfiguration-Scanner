"""
Module: aws_helpers
Description:
    Provides helper functions for initializing AWS service clients using boto3.
    The helper reads AWS credentials from environment variables and returns a boto3 client.
"""

import boto3
import os

def get_aws_client(service_name, region_name):
    """
    Initialize and return a boto3 client for the specified AWS service.
    
    This helper function attempts to create an AWS client using environment variables
    for credentials. If the client creation fails, an error message is printed and None is returned.
    
    Args:
        service_name (str): The name of the AWS service (e.g., 's3', 'ec2', 'iam').
        region_name (str): The AWS region name (e.g., 'ap-northeast-1').
    
    Returns:
        boto3.client or None: The initialized client for the requested service, or None if initialization fails.
    """
    try:
        client = boto3.client(
            service_name,
            region_name=region_name,
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            aws_session_token=os.getenv('AWS_SESSION_TOKEN')
        )
        return client
    except Exception as e:
        print(f"Error initializing AWS client for {service_name}: {e}")
        return None
