"""
Module: s3_scanner
Description:
    Provides compliance scanning for Amazon S3 buckets by examining their public access settings,
    encryption configuration, and more. This module leverages various S3 API calls to check for common
    misconfigurations such as open ACLs, overly permissive bucket policies, and missing encryption.
    Each finding is assigned a risk score based on exposure, compliance violations, and impact.
"""

import json
from app.utils.aws_helpers import get_aws_client
from app.utils.logger import logger 
from botocore.exceptions import ClientError

# Constants for risk scoring
EXPOSURE_SCORES = {"High": 10, "Medium": 5, "Low": 1}
IMPACT_SCORES = {"Critical": 15, "High": 10, "Medium": 5}
COMPLIANCE_WEIGHT = 5  
WEIGHTS = {"exposure": 0.5, "compliance": 0.3, "impact": 0.2}
WORST_CASE_RAW_SCORE = 15 


class S3Scanner:
    """
    S3Scanner performs a series of compliance checks on Amazon S3 buckets.

    It checks for:
      - Public access via bucket ACLs, bucket policies, and public access block settings.
      - Encryption status for buckets.
    
    Each check yields findings that include risk scores and remediation recommendations.
    """

    def __init__(self, region='ap-northeast-1'):
        """
        Initialize the S3Scanner with an S3 client for the specified region.

        Args:
            region (str): The AWS region where the S3 buckets are located. Default is 'ap-northeast-1'.
        """
        self.s3_client = get_aws_client('s3', region)
        if self.s3_client:
            logger.info(f"S3 client initialized for region {region}.")
        else:
            logger.error("Failed to initialize S3 client.")

    def calculate_risk_score(self, exposure, compliance_violations, impact):
        """
        Calculate a normalized risk score on a 0-100 scale based on exposure, compliance violations, and impact.

        The method maps textual ratings to numerical scores using predefined dictionaries, applies
        weighted contributions to each component, and then normalizes the raw score by a worst-case factor.

        Args:
            exposure (str): The exposure level (e.g., "High", "Medium", or "Low").
            compliance_violations (int): The number of compliance violations.
            impact (str): The impact level (e.g., "Critical", "High", or "Medium").

        Returns:
            float: A normalized risk score rounded to two decimal places.
        """
        exposure_score = EXPOSURE_SCORES.get(exposure, 0)
        impact_score = IMPACT_SCORES.get(impact, 0)
        compliance_score = compliance_violations * COMPLIANCE_WEIGHT

        raw_score = (
            WEIGHTS["exposure"] * exposure_score +
            WEIGHTS["compliance"] * compliance_score +
            WEIGHTS["impact"] * impact_score
        )
        normalized_score = (raw_score / WORST_CASE_RAW_SCORE) * 100
        return round(normalized_score, 2)

    def scan_buckets_public_access(self):
        """
        Scan all S3 buckets for public access issues.

        This method iterates over each bucket returned by list_buckets(), and for each bucket it:
          - Scans the bucket ACL for overly permissive grants.
          - Checks the Public Access Block configuration.
          - Examines the bucket policy for public access allowances.
        
        Returns:
            list: A list of dictionaries where each dictionary describes a public access finding,
                  including the bucket name, issue description, risk level, risk score, and recommendation.
        """
        findings = []
        try:
            response = self.s3_client.list_buckets()
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                logger.info(f"Scanning bucket '{bucket_name}' for public access.")
                
                # Scan bucket ACL for public access grants.
                acl_findings = self.scan_bucket_acl(bucket_name)
                if acl_findings:
                    if isinstance(acl_findings, list):
                        findings.extend(acl_findings)
                    else:
                        findings.append(acl_findings)

                # Scan the Public Access Block configuration.
                pab_findings = self.scan_bucket_public_access_block(bucket_name)
                if pab_findings:
                    findings.append(pab_findings)

                # Scan the bucket policy for overly permissive access.
                policy_findings = self.scan_bucket_policy_public_access(bucket_name)
                if policy_findings:
                    findings.append(policy_findings)

            return findings
        except Exception as e:
            logger.exception(f"Error scanning S3 buckets for public access: {e}")
            return findings

    def scan_bucket_public_access_block(self, bucket_name):
        """
        Check the Public Access Block configuration for the specified bucket.

        Determines whether all critical public access block settings are enabled. If any required
        settings are missing, a finding is generated.

        Args:
            bucket_name (str): The name of the S3 bucket.
        
        Returns:
            dict or None: A dictionary containing the finding if there's a misconfiguration; otherwise, None.
        """
        try:
            response = self.s3_client.get_public_access_block(Bucket=bucket_name)
            config = response.get('PublicAccessBlockConfiguration', {})
            logger.info(f"Public Access Block Config for bucket '{bucket_name}': {config}")
            # Check if both BlockPublicAcls and IgnorePublicAcls are enabled.
            if not config.get('BlockPublicAcls') or not config.get('IgnorePublicAcls'):
                risk_level = "Medium"
                compliance_violations = 3
                exposure = "High"  
                risk_score = self.calculate_risk_score(exposure, compliance_violations, risk_level)
                return {
                    "BucketName": bucket_name,
                    "Issue": "Public access block is not fully enabled.",
                    "RiskLevel": risk_level,
                    "RiskScore": risk_score,
                    "Recommendation": f"Enable Public Access Block settings for the bucket '{bucket_name}'."
                }
            return None
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                # No configuration exists, which is flagged as a misconfiguration.
                risk_level = "Medium"
                compliance_violations = 3
                exposure = "High"
                risk_score = self.calculate_risk_score(exposure, compliance_violations, risk_level)
                return {
                    "BucketName": bucket_name,
                    "Issue": "No Public Access Block configuration found.",
                    "RiskLevel": risk_level,
                    "RiskScore": risk_score,
                    "Recommendation": f"Add Public Access Block settings for the bucket '{bucket_name}'."
                }
            else:
                logger.warning(f"Error retrieving public access block for bucket '{bucket_name}': {e}")
            return None

    def scan_bucket_location(self, bucket_name):
        """
        Retrieve and log the geographical location of the specified bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.
        """
        try:
            location = self.s3_client.get_bucket_location(Bucket=bucket_name)
            logger.info(f"Bucket '{bucket_name}' location: {location}")
        except ClientError as e:
            logger.error(f"Error retrieving location for bucket '{bucket_name}': {e}")

    def scan_bucket_acl(self, bucket_name):
        """
        Scan the Access Control List (ACL) of a bucket for public access grants.

        Checks each ACL grant for a grantee with the URI for "AllUsers". If found, a finding is generated.

        Args:
            bucket_name (str): The name of the S3 bucket.
        
        Returns:
            list or None: A list of dictionaries describing ACL findings if any public access is found;
                          otherwise, None.
        """
        try:
            acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            logger.info(f"ACL for bucket '{bucket_name}': {acl}")
            findings = []
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    risk_level = "High"
                    compliance_violations = 3
                    exposure = "High"
                    risk_score = self.calculate_risk_score(exposure, compliance_violations, risk_level)
                    findings.append({
                        "BucketName": bucket_name,
                        "Issue": "Bucket ACL allows public access",
                        "Permission": grant.get('Permission'),
                        "RiskLevel": risk_level,
                        "RiskScore": risk_score,
                        "Recommendation": f"Update the bucket ACL for '{bucket_name}' to restrict public access."
                    })
            return findings if findings else None
        except ClientError as e:
            logger.warning(f"Error retrieving ACL for bucket '{bucket_name}': {e}")
            return None

    def scan_bucket_policy_public_access(self, bucket_name):
        """
        Scan the bucket policy for statements that allow public access.

        The method examines each statement in the bucket policy to determine if it allows access
        to all principals ("*"). If found, a finding is generated.

        Args:
            bucket_name (str): The name of the S3 bucket.
        
        Returns:
            dict or None: A dictionary describing the finding if an overly permissive policy is detected;
                          otherwise, None.
        """
        try:
            policy_response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response['Policy'])
            logger.info(f"Policy for bucket '{bucket_name}': {json.dumps(policy, indent=2)}")
            for statement in policy.get('Statement', []):
                # Check if the statement explicitly allows public access.
                if statement.get('Effect') == "Allow" and statement.get('Principal') == "*":
                    risk_level = "Critical"
                    compliance_violations = 3
                    exposure = "High"
                    risk_score = self.calculate_risk_score(exposure, compliance_violations, risk_level)
                    return {
                        "BucketName": bucket_name,
                        "Issue": "Bucket policy allows public access",
                        "RiskLevel": risk_level,
                        "RiskScore": risk_score,
                        "Recommendation": f"Update the bucket policy for '{bucket_name}' to restrict access."
                    }
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                logger.warning(f"Error retrieving policy for bucket '{bucket_name}': {e}")
        return None
    
    def scan_buckets_encryption(self):
        """
        Scan all S3 buckets to verify if server-side encryption is enabled.

        For each bucket that does not enforce encryption using AES256 or AWS KMS, a high-risk
        finding is generated.

        Returns:
            list: A list of dictionaries describing buckets that lack proper encryption settings.
        """
        if not self.s3_client:
            logger.error("S3 client not initialized.")
            return []

        try:
            response = self.s3_client.list_buckets()
            buckets = response['Buckets']
            findings = []
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
                    rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                    # Check if any rule enforces AES256 or AWS KMS encryption.
                    if not any(rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm') in ['AES256', 'aws:kms'] for rule in rules):
                        risk_level = "High"
                        compliance_violations = 3
                        exposure = "High"
                        risk_score = self.calculate_risk_score(exposure, compliance_violations, risk_level)
                        findings.append({
                            "BucketName": bucket_name,
                            "Issue": "Bucket does not have encryption enabled.",
                            "RiskLevel": risk_level,
                            "RiskScore": risk_score,
                            "Recommendation": f"Enable server-side encryption for the bucket '{bucket_name}' using AES256 or AWS KMS."
                        })
                except Exception as e:
                    # Handle the case where encryption configuration is not found.
                    if isinstance(e, ClientError) and e.response.get("Error", {}).get("Code") == "ServerSideEncryptionConfigurationNotFoundError":
                        risk_level = "High"
                        compliance_violations = 3
                        exposure = "High"
                        risk_score = self.calculate_risk_score(exposure, compliance_violations, risk_level)
                        findings.append({
                            "BucketName": bucket_name,
                            "Issue": "Bucket does not have encryption enabled.",
                            "RiskLevel": risk_level,
                            "RiskScore": risk_score,
                            "Recommendation": f"Enable server-side encryption for the bucket '{bucket_name}' using AES256 or AWS KMS."
                        })
                    else:
                        logger.exception(f"Error retrieving encryption for bucket {bucket_name}: {e}")
            logger.info("Completed scanning S3 buckets for encryption.")
            return findings
        except Exception as e:
            logger.exception(f"Error scanning S3 buckets for encryption: {e}")
            return []

    def run_all_checks(self):
        """
        Run all S3 compliance checks and aggregate the findings.

        The method aggregates public access findings (from ACLs, policies, and Public Access Block)
        and encryption findings, and returns a results dictionary for further processing.

        Returns:
            dict: A dictionary with keys "PublicAccess" and "Encryption", each containing the corresponding findings.
        """
        logger.info("Running all S3 checks...")
        results = {
            "PublicAccess": self.scan_buckets_public_access(),
            "Encryption": self.scan_buckets_encryption()
        }
        logger.info("Completed all S3 checks.")
        return results
