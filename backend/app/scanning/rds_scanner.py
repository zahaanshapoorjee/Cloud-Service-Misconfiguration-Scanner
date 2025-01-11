"""
Module: rds_scanner
Description:
    Provides compliance scanning for Amazon RDS instances and parameter groups.
    This module checks for common misconfigurations in RDS services including:
      - Unencrypted RDS instances.
      - Publicly accessible RDS instances.
      - DB parameter groups that do not enforce SSL connections.
      
    Each finding is scored based on exposure, compliance violations, and impact levels,
    and remediation recommendations are provided.
"""

import datetime
from app.utils.aws_helpers import get_aws_client
from app.utils.logger import logger 

# Constants for risk score calculations.
EXPOSURE_SCORES = {"Critical": 10, "High": 8, "Medium": 5, "Low": 3}
IMPACT_SCORES = {"Critical": 15, "High": 10, "Medium": 5, "Low": 3}
COMPLIANCE_WEIGHT = 5  
WEIGHTS = {"exposure": 0.4, "compliance": 0.3, "impact": 0.3}
WORST_CASE_RAW_SCORE = 15  


class RDSScanner:
    """
    RDSScanner performs security and compliance assessments on Amazon RDS resources.

    It includes methods to identify:
      - RDS instances lacking encryption at rest.
      - RDS instances that are publicly accessible.
      - Parameter groups misconfigured to enforce SSL.
    
    Each scan calculates a normalized risk score and provides remediation recommendations.
    """

    def __init__(self, region='ap-northeast-1'):
        """
        Initialize the RDSScanner with an AWS RDS client.

        Args:
            region (str): The AWS region where the RDS resources are located. Default is 'ap-northeast-1'.
        """
        self.rds_client = get_aws_client('rds', region)

    def calculate_risk_score(self, exposure, compliance_violations, impact):
        """
        Calculate and normalize a risk score for a given finding.

        The risk score is computed using predefined scores for exposure and impact, as well as
        a compliance multiplier. The raw score is computed using weighted factors and then
        normalized to a scale of 0 to 100.

        Args:
            exposure (str): Exposure level (e.g., "Critical", "High", "Medium", "Low").
            compliance_violations (int): The number of compliance violations for the finding.
            impact (str): Impact level (e.g., "Critical", "High", "Medium", "Low").

        Returns:
            float: Normalized risk score, rounded to two decimals.
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

    def scan_unencrypted_databases(self):
        """
        Scan for RDS instances that do not have encryption at rest enabled.

        For each unencrypted RDS instance, this method calculates a risk score and generates
        a finding with a recommendation to enable encryption.

        Returns:
            list: A list of dictionaries containing details about each unencrypted RDS instance.
        """
        if not self.rds_client:
            logger.error("RDS client not initialized.")
            return []

        findings = []
        try:
            # Retrieve all RDS instances.
            response = self.rds_client.describe_db_instances()
            for db in response.get('DBInstances', []):
                # Check if the instance is not encrypted.
                if not db.get('StorageEncrypted', False):
                    risk_level = "High"
                    compliance_violations = 3  # Example static value for demonstration.
                    risk_score = self.calculate_risk_score(
                        exposure=risk_level,
                        compliance_violations=compliance_violations,
                        impact="High"
                    )
                    findings.append({
                        "DBInstanceIdentifier": db['DBInstanceIdentifier'],
                        "StorageEncrypted": db.get('StorageEncrypted', False),
                        "RiskLevel": risk_level,
                        "RiskScore": risk_score,
                        "Recommendation": f"Enable encryption at rest for the RDS instance '{db['DBInstanceIdentifier']}'."
                    })
            logger.info("Completed scanning RDS instances for encryption.")
            return findings
        except Exception as e:
            logger.exception("Error scanning RDS instances for encryption:")
            return []

    def scan_public_accessible_databases(self):
        """
        Scan for RDS instances that are publicly accessible.

        This method examines RDS instance configurations and generates a critical risk finding
        for instances that have public accessibility enabled, along with a remediation recommendation.

        Returns:
            list: A list of dictionaries containing details about each publicly accessible RDS instance.
        """
        if not self.rds_client:
            logger.error("RDS client not initialized.")
            return []

        findings = []
        try:
            # Retrieve all RDS instances.
            response = self.rds_client.describe_db_instances()
            for db in response.get('DBInstances', []):
                # Check if the instance is publicly accessible.
                if db.get('PubliclyAccessible', False):
                    risk_level = "Critical"
                    compliance_violations = 3  # Example static value.
                    risk_score = self.calculate_risk_score(
                        exposure=risk_level,
                        compliance_violations=compliance_violations,
                        impact="Critical"
                    )
                    findings.append({
                        "DBInstanceIdentifier": db['DBInstanceIdentifier'],
                        "PubliclyAccessible": db.get('PubliclyAccessible', False),
                        "RiskLevel": risk_level,
                        "RiskScore": risk_score,
                        "Recommendation": f"Modify the instance '{db['DBInstanceIdentifier']}' to disable public accessibility."
                    })
            logger.info("Completed scanning RDS instances for public accessibility.")
            return findings
        except Exception as e:
            logger.exception("Error scanning RDS instances for public accessibility:")
            return []

    def scan_db_parameter_groups(self):
        """
        Scan RDS parameter groups for settings that do not enforce SSL.

        Specifically, this method checks for the parameter 'rds.force_ssl' to ensure it is set to '1'.
        If this parameter is misconfigured, a high risk is assigned, and a recommendation is provided.

        Returns:
            list: A list of dictionaries containing details about non-compliant parameter groups.
        """
        if not self.rds_client:
            logger.error("RDS client not initialized.")
            return []

        findings = []
        try:
            # Retrieve all database parameter groups.
            response = self.rds_client.describe_db_parameter_groups()
            for pg in response.get('DBParameterGroups', []):
                pg_name = pg['DBParameterGroupName']
                # Retrieve parameters for each parameter group.
                params_response = self.rds_client.describe_db_parameters(DBParameterGroupName=pg_name)
                for param in params_response.get('Parameters', []):
                    # Check if 'rds.force_ssl' is not set to '1'.
                    if param.get('ParameterName') == 'rds.force_ssl' and param.get('ParameterValue') != '1':
                        risk_level = "High"
                        compliance_violations = 3  # Example static value.
                        risk_score = self.calculate_risk_score(
                            exposure=risk_level,
                            compliance_violations=compliance_violations,
                            impact="High"
                        )
                        findings.append({
                            "DBParameterGroupName": pg_name,
                            "ParameterName": param.get('ParameterName'),
                            "CurrentValue": param.get('ParameterValue'),
                            "Issue": "Parameter group does not enforce SSL (rds.force_ssl not set to '1').",
                            "RiskLevel": risk_level,
                            "RiskScore": risk_score,
                            "Recommendation": f"Set 'rds.force_ssl' to '1' for parameter group '{pg_name}' to enforce SSL connections."
                        })
            logger.info("Completed scanning RDS parameter groups.")
            return findings
        except Exception as e:
            logger.exception("Error scanning RDS parameter groups:")
            return []

    def run_all_compliance_checks(self):
        """
        Run all RDS compliance checks and aggregate the findings.

        The method aggregates findings for unencrypted instances, publicly accessible instances,
        and misconfigured parameter groups into a single dictionary.

        Returns:
            dict: A dictionary with the following keys and their corresponding findings:
                  - "UnencryptedInstances"
                  - "PublicInstances"
                  - "ParameterGroupIssues"
        """
        logger.info("Running RDS compliance checks...")
        results = {
            "UnencryptedInstances": self.scan_unencrypted_databases(),
            "PublicInstances": self.scan_public_accessible_databases(),
            "ParameterGroupIssues": self.scan_db_parameter_groups()
        }
        logger.info("Completed RDS compliance checks.")
        return results
