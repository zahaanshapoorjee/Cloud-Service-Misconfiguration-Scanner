"""
Module: rds_compliance_scanner
Description:
    Implements compliance scanning for Amazon RDS instances and parameter groups.
    This module checks for common misconfigurations in RDS services including
    unencrypted instances, publicly accessible instances, and non-compliant parameter groups.
    Each finding is scored based on exposure, compliance violations, and impact, and
    recommendations are provided for remediation.
"""

import datetime
from app.utils.aws_helpers import get_aws_client
from app.utils.logger import logger 

# Risk score calculation constants
EXPOSURE_SCORES = {"Critical": 10, "High": 8, "Medium": 5, "Low": 3}
IMPACT_SCORES = {"Critical": 15, "High": 10, "Medium": 5, "Low": 3}
COMPLIANCE_WEIGHT = 5  
WEIGHTS = {"exposure": 0.4, "compliance": 0.3, "impact": 0.3}
WORST_CASE_RAW_SCORE = 15  


class RDSComplianceScanner:
    """
    RDSComplianceScanner performs compliance checks on Amazon RDS resources.

    It checks for:
      - RDS instances without encryption at rest.
      - RDS instances that are publicly accessible.
      - DB parameter groups with parameters that violate SSL enforcement requirements.
    
    Risk scores are calculated using weighted factors based on exposure, compliance
    violations, and impact, and remediations are recommended for each finding.
    """

    def __init__(self, region='ap-northeast-1'):
        """
        Initialize the RDSComplianceScanner with an AWS RDS client.

        Args:
            region (str): The AWS region where the RDS resources reside. Default is 'ap-northeast-1'.
        """
        self.rds_client = get_aws_client('rds', region)

    def calculate_risk_score(self, exposure, compliance_violations, impact):
        """
        Calculate and normalize the risk score for a given finding.

        The risk score is computed using predefined numerical values for exposure and impact,
        multiplied by their respective weights along with a compliance weight. The raw score is
        then normalized to a scale of 0 to 100 based on the worst-case raw score.

        Args:
            exposure (str): Exposure level (e.g., "Critical", "High", "Medium", "Low").
            compliance_violations (int): The number of compliance violations identified.
            impact (str): Impact level (e.g., "Critical", "High", "Medium", "Low").

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

    def scan_unencrypted_instances(self):
        """
        Scan for RDS instances that do not have encryption at rest enabled.

        For each unencrypted RDS instance, a risk score is calculated and a finding is generated
        along with a remediation recommendation.

        Returns:
            list: A list of dictionaries, each containing details about an unencrypted RDS instance.
        """
        findings = []
        if not self.rds_client:
            logger.error("RDS client not initialized.")
            return findings
        try:
            # Retrieve all RDS instances.
            response = self.rds_client.describe_db_instances()
            for db in response.get('DBInstances', []):
                # Check if the instance does not have encryption enabled.
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
                        "Issue": "RDS instance is not encrypted at rest.",
                        "RiskLevel": risk_level,
                        "RiskScore": risk_score,
                        "Recommendation": f"Enable encryption at rest for the RDS instance '{db['DBInstanceIdentifier']}'."
                    })
            logger.info("Completed scanning RDS instances for encryption.")
            return findings
        except Exception as e:
            logger.exception("Error in scan_unencrypted_instances:")
            return findings

    def scan_public_instances(self):
        """
        Scan for publicly accessible RDS instances.

        Checks each RDS instance for the 'PubliclyAccessible' flag. For instances that are publicly accessible,
        a finding is created with a corresponding critical risk score and a recommendation to disable public access.

        Returns:
            list: A list of dictionaries containing details about each publicly accessible RDS instance.
        """
        findings = []
        if not self.rds_client:
            logger.error("RDS client not initialized.")
            return findings
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
                        "Issue": "RDS instance is publicly accessible.",
                        "RiskLevel": risk_level,
                        "RiskScore": risk_score,
                        "Recommendation": f"Modify the instance '{db['DBInstanceIdentifier']}' to disable public accessibility."
                    })
            logger.info("Completed scanning RDS instances for public accessibility.")
            return findings
        except Exception as e:
            logger.exception("Error in scan_public_instances:")
            return findings

    def scan_db_parameter_groups(self):
        """
        Scan RDS parameter groups for misconfigurations that may affect security.

        Specifically, this method checks if the parameter group enforces SSL by verifying that
        the 'rds.force_ssl' parameter is set to '1'. A non-compliant parameter group is flagged
        with a high risk and a recommendation to enforce SSL.

        Returns:
            list: A list of dictionaries detailing non-compliant parameter groups and their issues.
        """
        findings = []
        if not self.rds_client:
            logger.error("RDS client not initialized.")
            return findings
        try:
            # Retrieve all DB parameter groups.
            response = self.rds_client.describe_db_parameter_groups()
            for pg in response.get('DBParameterGroups', []):
                pg_name = pg['DBParameterGroupName']
                # Retrieve parameters for the parameter group.
                params = self.rds_client.describe_db_parameters(DBParameterGroupName=pg_name)
                for param in params.get('Parameters', []):
                    # Check if the parameter 'rds.force_ssl' is set correctly.
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
            logger.exception("Error in scan_db_parameter_groups:")
            return findings

    def run_all_compliance_checks(self):
        """
        Run all RDS compliance checks and aggregate the findings.

        For demonstration, different compliance frameworks (CIS, NIST, PCI) are mapped to similar checks,
        with slight variations in the reported findings. This structure can be extended for custom rules.

        Returns:
            dict: A dictionary containing compliance findings under keys "CIS", "NIST", and "PCI".
        """
        logger.info("Running RDS compliance checks...")

        cis_findings = {
            "UnencryptedInstances": self.scan_unencrypted_instances(),
            "PublicInstances": self.scan_public_instances(),
            "ParameterGroups": self.scan_db_parameter_groups()
        }

        nist_findings = {
            "UnencryptedInstances": self.scan_unencrypted_instances(),
            "PublicInstances": self.scan_public_instances()
        }

        pci_findings = {
            "PublicInstances": self.scan_public_instances(),
            "UnencryptedInstances": self.scan_unencrypted_instances()
        }

        results = {
            "CIS": cis_findings,
            "NIST": nist_findings,
            "PCI": pci_findings
        }

        logger.info("Completed RDS compliance checks.")
        return results
