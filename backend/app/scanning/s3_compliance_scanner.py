"""
Module: s3_compliance_scanner
Description:
    Provides compliance scanning for Amazon S3 buckets by checking key security configurations.
    This module scans for public access, logging, encryption, versioning, and overly permissive bucket policies.
    Each finding is scored based on exposure, compliance violations, and impact, with remediation recommendations provided.
"""

import json
import boto3
from botocore.exceptions import ClientError
from app.utils.aws_helpers import get_aws_client
from app.utils.logger import logger  

# Constants for risk scoring
EXPOSURE_SCORES = {"Critical": 10, "High": 8, "Medium": 5, "Low": 3}
IMPACT_SCORES = {"Critical": 15, "High": 10, "Medium": 5, "Low": 3}
COMPLIANCE_WEIGHT = 5  
WEIGHTS = {"exposure": 0.4, "compliance": 0.3, "impact": 0.3}
WORST_CASE_RAW_SCORE = 15  


class S3ComplianceScanner:
    """
    S3ComplianceScanner performs a series of compliance checks on Amazon S3 buckets.

    Checks include:
      - Public access via ACLs and bucket policies.
      - Whether public access block settings are fully enabled.
      - If server-side encryption is enforced.
      - If bucket logging is enabled.
      - If versioning is enabled.
      - If bucket policies overly restrict access (violating PCI requirements).

    Risk scores are calculated based on the level of exposure, the number of compliance violations,
    and the impact of the misconfiguration.
    """

    def __init__(self, region='ap-northeast-1'):
        """
        Initialize the S3ComplianceScanner with an S3 client for the specified region.

        Args:
            region (str): The AWS region where the S3 buckets are hosted. Default is 'ap-northeast-1'.
        """
        self.s3_client = get_aws_client('s3', region)

    def calculate_risk_score(self, exposure, compliance_violations, impact):
        """
        Calculate and return a normalized risk score (scale 0-100).

        The raw score is calculated by applying predefined weights to the numerical values of exposure,
        compliance violations, and impact; then normalized using WORST_CASE_RAW_SCORE.

        Args:
            exposure (str): The exposure level ("Critical", "High", "Medium", "Low").
            compliance_violations (int): Number of compliance violations.
            impact (str): The impact level ("Critical", "High", "Medium", "Low").

        Returns:
            float: Normalized risk score rounded to two decimals.
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

    def scan_s3_public_access(self):
        """
        Scan S3 buckets for configurations that allow public access via ACL or bucket policies.

        The method:
          - Checks bucket ACLs for grants to the AllUsers group.
          - Checks bucket policies for statements that allow public access.
          - Examines the Public Access Block configuration.
        
        Returns:
            list: A list of dictionaries. Each dictionary describes a finding with details,
                  risk level, risk score, and a recommendation for remediation.
        """
        findings = []
        try:
            buckets = self.s3_client.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                logger.info(f"Scanning bucket '{bucket_name}' for public access.")

                # Check bucket ACLs
                try:
                    acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') == "http://acs.amazonaws.com/groups/global/AllUsers":
                            # Public access granted via ACL.
                            exposure = "High"
                            impact = "High"
                            compliance_violations = 3 
                            risk_score = self.calculate_risk_score(exposure, compliance_violations, impact)
                            findings.append({
                                "BucketName": bucket_name,
                                "Issue": "Bucket is publicly accessible via ACL",
                                "Permission": grant.get('Permission'),
                                "RiskLevel": "High",
                                "RiskScore": risk_score,
                                "Recommendation": f"Restrict ACL permissions for the bucket '{bucket_name}' to specific users or roles."
                            })
                except ClientError as e:
                    if e.response['Error']['Code'] == "NoSuchBucket":
                        logger.warning(f"Bucket '{bucket_name}' does not exist or is deleted.")
                    else:
                        logger.warning(f"Error retrieving ACL for bucket '{bucket_name}': {e}")

                # Check bucket policies
                try:
                    policy_response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_doc = json.loads(policy_response['Policy'])
                    for statement in policy_doc.get('Statement', []):
                        if statement.get('Effect') == "Allow":
                            principal = statement.get('Principal')
                            if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                                # Bucket policy allows public access.
                                exposure = "Critical"
                                impact = "Critical"
                                compliance_violations = 3
                                risk_score = self.calculate_risk_score(exposure, compliance_violations, impact)
                                findings.append({
                                    "BucketName": bucket_name,
                                    "Issue": "Bucket policy allows public access",
                                    "RiskLevel": "Critical",
                                    "RiskScore": risk_score,
                                    "Recommendation": f"Update the bucket policy for '{bucket_name}' to restrict public access."
                                })
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                        logger.warning(f"Error retrieving bucket policy for bucket '{bucket_name}': {e}")

                # Check Public Access Block settings
                try:
                    response = self.s3_client.get_public_access_block(Bucket=bucket_name)
                    config = response.get('PublicAccessBlockConfiguration', {})
                    logger.info(f"Public Access Block Config for bucket '{bucket_name}': {config}")
                    # Verify all critical public access block settings are enabled.
                    if not all(config.get(key, False) for key in ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets']):
                        exposure = "Medium"
                        impact = "Medium"
                        compliance_violations = 3
                        risk_score = self.calculate_risk_score(exposure, compliance_violations, impact)
                        findings.append({
                            "BucketName": bucket_name,
                            "Issue": "Public access block is not fully enabled.",
                            "RiskLevel": "Medium",
                            "RiskScore": risk_score,
                            "Recommendation": f"Enable Public Access Block settings for the bucket '{bucket_name}' to prevent public access."
                        })
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        # No public access block config; flag as medium risk.
                        exposure = "Medium"
                        impact = "Medium"
                        compliance_violations = 3
                        risk_score = self.calculate_risk_score(exposure, compliance_violations, impact)
                        findings.append({
                            "BucketName": bucket_name,
                            "Issue": "No Public Access Block configuration found.",
                            "RiskLevel": "Medium",
                            "RiskScore": risk_score,
                            "Recommendation": f"Add Public Access Block settings for the bucket '{bucket_name}'."
                        })
                    else:
                        logger.warning(f"Error retrieving public access block for bucket '{bucket_name}': {e}")

            logger.info("Completed scanning S3 public access.")
            return findings
        except Exception as e:
            logger.exception("Error scanning S3 public access:")
            return findings

    def scan_s3_logging_enabled(self):
        """
        Scan S3 buckets to determine if logging is enabled.

        For each bucket that does not have logging enabled, a risk score and finding are generated.

        Returns:
            list: A list of dictionaries containing details about buckets with logging disabled.
        """
        findings = []
        try:
            buckets = self.s3_client.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    logging_config = self.s3_client.get_bucket_logging(Bucket=bucket_name)
                    # If logging is not enabled (no "LoggingEnabled" key), flag the bucket.
                    if 'LoggingEnabled' not in logging_config:
                        exposure = "Medium"
                        impact = "Medium"
                        compliance_violations = 1 
                        risk_score = self.calculate_risk_score(exposure, compliance_violations, impact)
                        findings.append({
                            "BucketName": bucket_name,
                            "Issue": "Bucket logging is not enabled",
                            "RiskLevel": "Medium",
                            "RiskScore": risk_score,
                            "Recommendation": f"Enable logging for the bucket '{bucket_name}' to track access and activities."
                        })
                except ClientError as e:
                    logger.exception(f"Error retrieving logging config for {bucket_name}: {e}")
            logger.info("Completed scanning S3 logging configuration.")
            return findings
        except Exception as e:
            logger.exception("Error scanning S3 logging:")
            return findings

    def scan_s3_encryption_enabled(self):
        """
        Scan S3 buckets to verify if server-side encryption is enforced.

        For each bucket, if server-side encryption is not enabled using AES256 or AWS KMS,
        a high-risk finding is generated.

        Returns:
            list: A list of dictionaries describing buckets that do not enforce encryption at rest.
        """
        findings = []
        try:
            buckets = self.s3_client.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
                    rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                    # Check if any rule enforces either AES256 or AWS KMS.
                    if not any(rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm') in ['AES256', 'aws:kms'] for rule in rules):
                        exposure = "High"
                        impact = "High"
                        compliance_violations = 3
                        risk_score = self.calculate_risk_score(exposure, compliance_violations, impact)
                        findings.append({
                            "BucketName": bucket_name,
                            "Issue": "Bucket does not enforce encryption at rest",
                            "RiskLevel": "High",
                            "RiskScore": risk_score,
                            "Recommendation": f"Enable server-side encryption for the bucket '{bucket_name}' using AES256 or AWS KMS."
                        })
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        exposure = "High"
                        impact = "High"
                        compliance_violations = 3
                        risk_score = self.calculate_risk_score(exposure, compliance_violations, impact)
                        findings.append({
                            "BucketName": bucket_name,
                            "Issue": "Bucket does not enforce encryption at rest",
                            "RiskLevel": "High",
                            "RiskScore": risk_score,
                            "Recommendation": f"Enable server-side encryption for the bucket '{bucket_name}' using AES256 or AWS KMS."
                        })
                    else:
                        logger.exception(f"Error retrieving encryption for {bucket_name}: {e}")
            logger.info("Completed scanning S3 encryption.")
            return findings
        except Exception as e:
            logger.exception("Error scanning S3 encryption:")
            return findings

    def scan_s3_versioning_enabled(self):
        """
        Scan S3 buckets to verify if versioning is enabled.

        For buckets without versioning enabled, a finding is generated with a corresponding risk score.

        Returns:
            list: A list of dictionaries containing details about buckets with versioning disabled.
        """
        findings = []
        try:
            buckets = self.s3_client.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    versioning_config = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
                    if versioning_config.get('Status') != 'Enabled':
                        exposure = "Medium"
                        impact = "Medium"
                        compliance_violations = 1  
                        risk_score = self.calculate_risk_score(exposure, compliance_violations, impact)
                        findings.append({
                            "BucketName": bucket_name,
                            "Issue": "Bucket versioning is not enabled",
                            "RiskLevel": "Medium",
                            "RiskScore": risk_score,
                            "Recommendation": f"Enable versioning for the bucket '{bucket_name}' to maintain historical object versions."
                        })
                except ClientError as e:
                    logger.exception(f"Error retrieving versioning config for {bucket_name}: {e}")
            logger.info("Completed scanning S3 versioning.")
            return findings
        except Exception as e:
            logger.exception("Error scanning S3 versioning:")
            return findings

    def scan_s3_policy_restrictions(self):
        """
        Scan S3 bucket policies for overly permissive settings that grant public access.

        The method checks for policy statements where the Principal is '*' or is defined as "*"
        in a dictionary, which may violate PCI requirements.

        Returns:
            list: A list of dictionaries detailing buckets with overly permissive policies.
        """
        findings = []
        try:
            buckets = self.s3_client.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    policy_response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_doc = json.loads(policy_response['Policy'])
                    for statement in policy_doc.get('Statement', []):
                        principal = statement.get('Principal')
                        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                            exposure = "Critical"
                            impact = "Critical"
                            compliance_violations = 3
                            risk_score = self.calculate_risk_score(exposure, compliance_violations, impact)
                            findings.append({
                                "BucketName": bucket_name,
                                "Issue": "Bucket policy grants overly permissive access (violates PCI requirements)",
                                "RiskLevel": "Critical",
                                "RiskScore": risk_score,
                                "Recommendation": f"Update the bucket policy for '{bucket_name}' to limit access to specific principals."
                            })
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                        logger.exception(f"Error retrieving bucket policy for {bucket_name}: {e}")
            logger.info("Completed scanning S3 bucket policies for PCI restrictions.")
            return findings
        except Exception as e:
            logger.exception("Error scanning S3 bucket policies for PCI:")
            return findings

    def run_all_compliance_checks(self):
        """
        Run all S3 compliance checks and aggregate the findings.

        Finds results for several compliance frameworks:
          - CIS: Public access, logging, and encryption.
          - NIST: Public access, encryption, and versioning.
          - PCI: Public access, encryption, and policy restrictions.

        Returns:
            dict: A dictionary with keys "CIS", "NIST", and "PCI" and corresponding findings.
        """
        logger.info("Running all S3 compliance checks...")
        try:
            cis_findings = {
                "PublicAccess": self.scan_s3_public_access(),
                "Logging": self.scan_s3_logging_enabled(),
                "Encryption": self.scan_s3_encryption_enabled()
            }
            
            nist_findings = {
                "PublicAccess": self.scan_s3_public_access(),
                "Encryption": self.scan_s3_encryption_enabled(),
                "Versioning": self.scan_s3_versioning_enabled()
            }
            
            pci_findings = {
                "PublicAccess": self.scan_s3_public_access(),
                "Encryption": self.scan_s3_encryption_enabled(),
                "PolicyRestrictions": self.scan_s3_policy_restrictions()
            }
            
            results = {
                "CIS": cis_findings,
                "NIST": nist_findings,
                "PCI": pci_findings
            }
            logger.info("Completed all S3 compliance checks.")
            return results
        except Exception as e:
            logger.exception("Error while running S3 compliance checks:")
            return {}
