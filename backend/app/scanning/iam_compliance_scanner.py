"""
Module: iam_compliance_scanner
Description:
    Implements IAM compliance scanning capabilities for AWS.
    This module contains the IAMComplianceScanner class which performs checks on IAM policies
    and the root account MFA configuration. The scanner calculates a normalized risk score based on
    exposure, compliance violations, and impact scores. It identifies overly permissive policies and
    missing MFA on the root account, and provides remediation recommendations.
"""

from app.utils.aws_helpers import get_aws_client
from app.utils.logger import logger  

# Risk calculation constants for IAM compliance checks.
EXPOSURE_SCORES = {"Critical": 10, "High": 8, "Medium": 5}
IMPACT_SCORES = {"Critical": 15, "High": 10, "Medium": 5}
COMPLIANCE_WEIGHT = 5  
WEIGHTS = {"exposure": 0.4, "compliance": 0.3, "impact": 0.3}
WORST_CASE_RAW_SCORE = 15  


class IAMComplianceScanner:
    """
    IAMComplianceScanner performs security and compliance checks on AWS IAM resources.

    It verifies if IAM policies grant excessive permissions (e.g., using wildcards for actions
    and resources) and checks if the root account has MFA enabled. Based on these checks,
    it calculates a risk score and suggests remediation recommendations.
    """

    def __init__(self, region="ap-northeast-1"):
        """
        Initialize the IAMComplianceScanner with an AWS IAM client.

        Args:
            region (str): AWS region for IAM operations. Default is "ap-northeast-1".
        """
        self.iam_client = get_aws_client("iam", region)

    def calculate_risk_score(self, exposure, compliance_violations, impact):
        """
        Calculate and normalize the risk score for a given finding.

        The risk score is derived from exposure, compliance violations (multiplied by a compliance weight),
        and impact scores. The raw score is then normalized to a percentage (0 to 100 scale).

        Args:
            exposure (str): The exposure level ("Critical", "High", or "Medium").
            compliance_violations (int): The number of compliance violations associated with the finding.
            impact (str): The impact level ("Critical", "High", or "Medium").

        Returns:
            float: The normalized risk score rounded to two decimal places.
        """
        # Map exposure and impact levels to numerical scores.
        exposure_score = EXPOSURE_SCORES.get(exposure, 0)
        impact_score = IMPACT_SCORES.get(impact, 0)
        # Compute a compliance score based on the number of violations.
        compliance_score = compliance_violations * COMPLIANCE_WEIGHT

        # Calculate the raw score using a weighted sum of the individual scores.
        raw_score = (
            WEIGHTS["exposure"] * exposure_score +
            WEIGHTS["compliance"] * compliance_score +
            WEIGHTS["impact"] * impact_score
        )
        # Normalize the score with reference to the worst-case scenario.
        normalized_score = (raw_score / WORST_CASE_RAW_SCORE) * 100
        return round(normalized_score, 2)

    def scan_overly_permissive_policies(self):
        """
        Scan IAM policies for overly permissive configurations.

        The method retrieves all locally defined and attached IAM policies, then examines their
        policy documents. If a policy grants full access (i.e., uses wildcards "*" for both actions and resources),
        it calculates a risk score and creates a finding with a remediation recommendation.

        Returns:
            list: A list of dictionaries where each dictionary contains details of a permissive policy
                  including its name, ARN, the identified issue, risk level, calculated risk score, and a recommendation.
        """
        findings = []
        if not self.iam_client:
            logger.error("IAM client not initialized.")
            return findings

        try:
            # Retrieve attached, local IAM policies.
            response = self.iam_client.list_policies(Scope="Local", OnlyAttached=True)
            for policy in response.get("Policies", []):
                policy_arn = policy["Arn"]
                policy_name = policy["PolicyName"]
                version_id = policy["DefaultVersionId"]
                # Get the default version of the policy document.
                policy_detail = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn, VersionId=version_id
                )
                document = policy_detail["PolicyVersion"]["Document"]
                # Ensure the statement is a list.
                statements = document.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                # Analyze each statement in the policy document.
                for statement in statements:
                    actions = statement.get("Action", [])
                    resources = statement.get("Resource", [])
                    # Normalize to list if values are provided as strings.
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]
                    # Identify overly permissive policies granting full access.
                    if "*" in actions and "*" in resources:
                        risk_level = self.calculate_risk_level(actions, resources)
                        compliance_violations = 3  # Static number for demonstration purposes.
                        # Set exposure based on the use of wildcard actions.
                        exposure = "Critical" if "*" in actions else "High"
                        # Calculate risk score.
                        risk_score = self.calculate_risk_score(
                            exposure=exposure,
                            compliance_violations=compliance_violations,
                            impact=risk_level,
                        )
                        recommendation = self.generate_recommendation(policy_name)
                        findings.append({
                            "PolicyName": policy_name,
                            "PolicyArn": policy_arn,
                            "Issue": "Policy grants all actions on all resources, violating least privilege.",
                            "RiskLevel": risk_level,
                            "RiskScore": risk_score,
                            "Recommendation": recommendation,
                        })
            logger.info("Completed scanning IAM policies for overly permissive policies.")
            return findings
        except Exception as e:
            logger.exception("Error in scan_overly_permissive_policies:")
            return findings

    def scan_root_account_mfa(self):
        """
        Scan the AWS account to verify if root account MFA is enabled.

        Retrieves the account summary and checks the MFA status for the root account.
        If MFA is not enabled (i.e., count is less than 1), a finding is generated
        with a corresponding risk score and recommendation.

        Returns:
            list: A list containing a dictionary for the root account MFA finding if the MFA is not enabled;
                  otherwise, an empty list.
        """
        findings = []
        if not self.iam_client:
            logger.error("IAM client not initialized.")
            return findings

        try:
            response = self.iam_client.get_account_summary()
            mfa_count = response.get("SummaryMap", {}).get("AccountMFAEnabled", 0)
            # If MFA is not enabled, create a finding.
            if mfa_count < 1:
                risk_level = "Critical"
                compliance_violations = 3  # Static count for demonstration.
                exposure = "Critical"
                risk_score = self.calculate_risk_score(
                    exposure=exposure,
                    compliance_violations=compliance_violations,
                    impact=risk_level,
                )
                findings.append({
                    "Issue": "Root account does not have MFA enabled.",
                    "RiskLevel": risk_level,
                    "RiskScore": risk_score,
                    "Recommendation": "Enable MFA on the root account immediately to enhance security.",
                })
            logger.info("Completed root account MFA scan.")
            return findings
        except Exception as e:
            logger.exception("Error in scan_root_account_mfa:")
            return findings

    def run_all_compliance_checks(self):
        """
        Run all IAM compliance checks including MFA configuration and overly permissive policies.

        This method aggregates findings for different compliance standards such as CIS, NIST, and PCI.
        Each standard contains similar findings for demonstration, but the structure supports custom rules for each standard.

        Returns:
            dict: A dictionary with compliance standard names (e.g., 'CIS', 'NIST', 'PCI') as keys and
                  corresponding findings as values.
        """
        logger.info("Running IAM compliance checks...")

        cis_findings = {
            "RootMFA": self.scan_root_account_mfa(),
            "OverlyPermissivePolicies": self.scan_overly_permissive_policies(),
        }
        # For demonstration, the same findings are used for other standards.
        nist_findings = {
            "RootMFA": self.scan_root_account_mfa(),
            "OverlyPermissivePolicies": self.scan_overly_permissive_policies(),
        }
        pci_findings = {
            "RootMFA": self.scan_root_account_mfa(),
            "OverlyPermissivePolicies": self.scan_overly_permissive_policies(),
        }

        results = {
            "CIS": cis_findings,
            "NIST": nist_findings,
            "PCI": pci_findings,
        }
        logger.info("Completed IAM compliance checks.")
        return results

    def calculate_risk_level(self, actions, resources):
        """
        Determine the risk level for an IAM policy based on its actions and resources.

        Args:
            actions (list): List of actions defined in the policy statement.
            resources (list): List of resources defined in the policy statement.

        Returns:
            str: Risk level classification ("Critical", "High", or "Medium").
        """
        if "*" in actions and "*" in resources:
            return "Critical"
        elif "*" in actions:
            return "High"
        elif "*" in resources:
            return "High"
        else:
            return "Medium"

    def generate_recommendation(self, policy_name):
        """
        Generate a remediation recommendation for an overly permissive IAM policy.

        Args:
            policy_name (str): The name of the IAM policy.

        Returns:
            str: A recommendation advising how to restrict permissions and follow least privilege best practices.
        """
        return (
            f"Review and update the IAM policy '{policy_name}' to follow the principle of least privilege. "
            "Limit actions and resources to the minimum required for the policy's purpose."
        )
