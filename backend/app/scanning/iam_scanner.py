"""
Module: iam_scanner
Description:
    Provides IAM scanning capabilities to assess AWS IAM configurations against common compliance criteria.
    This module includes methods to scan for overly permissive policies, unused access keys, and root account MFA configuration.
    It calculates risk scores based on exposure, compliance violations, and impact levels, then generates remediation recommendations.
"""

import datetime
from app.utils.aws_helpers import get_aws_client
from app.utils.logger import logger  


class IAMScanner:
    """
    IAMScanner performs security and compliance assessments on AWS IAM resources.

    It includes methods to scan for overly permissive IAM policies, detect unused access keys,
    and verify that the root account has MFA enabled. Risk scores are calculated and normalized,
    and remediation recommendations are provided for any identified vulnerabilities.
    """

    def __init__(self, region='ap-northeast-1'):
        """
        Initialize the IAMScanner with an AWS IAM client.

        Args:
            region (str): AWS region where the IAM operations will be performed. Default is 'ap-northeast-1'.
        """
        self.iam_client = get_aws_client('iam', region)
    
    def calculate_risk_score(self, exposure, compliance_violations, impact):
        """
        Calculate a normalized risk score based on exposure, number of compliance violations, and impact.

        The method uses predefined scores for exposure and impact along with a compliance multiplier,
        then applies weighted factors to compute a raw score. This raw score is normalized based on a worst-case scenario.

        Args:
            exposure (str): The exposure level (e.g., "Critical", "High", "Medium", "Low").
            compliance_violations (int): The number of compliance violations associated with the finding.
            impact (str): The impact level (e.g., "Critical", "High", "Medium", "Low").

        Returns:
            float: The normalized risk score on a scale from 0 to 100, rounded to two decimals.
        """
        # Define scoring constants locally.
        EXPOSURE_SCORES = {"Critical": 10, "High": 8, "Medium": 5, "Low": 3}
        IMPACT_SCORES = {"Critical": 15, "High": 10, "Medium": 5, "Low": 3}
        COMPLIANCE_WEIGHT = 5  
        WEIGHTS = {"exposure": 0.4, "compliance": 0.3, "impact": 0.3}

        # Retrieve the corresponding score values for exposure and impact.
        exposure_score = EXPOSURE_SCORES.get(exposure, 0)
        impact_score = IMPACT_SCORES.get(impact, 0)
        # Multiply the number of compliance violations by the weight.
        compliance_score = compliance_violations * COMPLIANCE_WEIGHT

        # Calculate a raw score using weighted contributions.
        raw_score = (
            WEIGHTS["exposure"] * exposure_score +
            WEIGHTS["compliance"] * compliance_score +
            WEIGHTS["impact"] * impact_score
        )
        
        # Define worst-case raw score for normalization.
        WORST_CASE_RAW_SCORE = 15
        normalized_score = (raw_score / WORST_CASE_RAW_SCORE) * 100
        return round(normalized_score, 2)
    
    def scan_overly_permissive_policies(self):
        """
        Scan IAM policies for configurations that grant overly permissive access.

        Retrieves locally defined, attached policies and examines their default policy documents.
        If any policy's statement grants full access (using '*' for both Action and Resource),
        then a risk score is calculated and a finding is generated with remediation advice.

        Returns:
            list: A list of dictionaries, each containing details about an overly permissive policy.
        """
        if not self.iam_client:
            logger.error("IAM client not initialized.")
            return []
        
        findings = []
        try:
            # Retrieve all locally defined and attached IAM policies.
            response = self.iam_client.list_policies(Scope='Local', OnlyAttached=True)
            for policy in response['Policies']:
                policy_arn = policy['Arn']
                policy_name = policy['PolicyName']
                policy_version_id = policy['DefaultVersionId']
                # Retrieve the policy document for the default version.
                policy_detail = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_version_id
                )
                document = policy_detail['PolicyVersion']['Document']
                
                # Ensure the statement is always a list for uniform processing.
                statements = document.get('Statement', [])
                if isinstance(statements, dict):
                    statements = [statements]
                
                # Analyze each statement for overly permissive access.
                for statement in statements:
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', [])
                    
                    # Normalize actions and resources to lists if they are provided as strings.
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]
                    
                    # Identify statements that allow all actions on all resources.
                    if '*' in actions and '*' in resources:
                        risk_level = self.calculate_risk_level(actions, resources)
                        compliance_violations = 3  # Example static value.
                        # Calculate risk score using the risk level as the exposure metric.
                        risk_score = self.calculate_risk_score(
                            exposure=risk_level,
                            compliance_violations=compliance_violations,
                            impact="Critical"  
                        )
                        recommendation = self.generate_recommendation(policy_name)
                        findings.append({
                            "PolicyName": policy_name,
                            "PolicyArn": policy_arn,
                            "Statement": statement,
                            "RiskLevel": risk_level,
                            "RiskScore": risk_score,
                            "Recommendation": recommendation
                        })
            logger.info("Completed scanning IAM policies for overly permissive policies.")
            return findings
        except Exception as e:
            logger.exception("Error scanning IAM policies:")
            return []
    
    def scan_unused_access_keys(self):
        """
        Scan IAM users for access keys that have not been used within the last 90 days.

        For each user, the method checks the last used date for each access key. If an access key
        has not been used for over 90 days or has never been used, it is flagged and a corresponding
        risk score is calculated with recommendations to deactivate it.

        Returns:
            list: A list of dictionaries, each containing details about an unused access key.
        """
        if not self.iam_client:
            logger.error("IAM client not initialized.")
            return []
        
        findings = []
        try:
            # List all IAM users.
            response = self.iam_client.list_users()
            users = response['Users']
            for user in users:
                username = user['UserName']
                # Retrieve access keys for each user.
                access_keys = self.iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
                for key in access_keys:
                    key_id = key['AccessKeyId']
                    # Retrieve the last used information for the access key.
                    last_used = self.iam_client.get_access_key_last_used(AccessKeyId=key_id)
                    last_used_date = last_used['AccessKeyLastUsed'].get('LastUsedDate')
                    
                    # Calculate a timestamp representing 90 days ago.
                    ninety_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90)
                    
                    # If the access key has been used, compare its last used date with the threshold.
                    if last_used_date:
                        # Ensure the datetime object is timezone-aware.
                        if last_used_date.tzinfo is None:
                            last_used_date = last_used_date.replace(tzinfo=datetime.timezone.utc)
                        if last_used_date < ninety_days_ago:
                            risk_score = self.calculate_risk_score(
                                exposure="Medium",
                                compliance_violations=1,  
                                impact="Medium"
                            )
                            findings.append({
                                "UserName": username,
                                "AccessKeyId": key_id,
                                "LastUsedDate": last_used_date.isoformat(),
                                "RiskLevel": "Medium",
                                "RiskScore": risk_score,
                                "Recommendation": f"Deactivate unused access key '{key_id}' for user '{username}' or verify its necessity."
                            })
                    else:
                        # Consider keys that have never been used as high risk.
                        risk_score = self.calculate_risk_score(
                            exposure="High",
                            compliance_violations=2,
                            impact="High"
                        )
                        findings.append({
                            "UserName": username,
                            "AccessKeyId": key_id,
                            "LastUsedDate": "Never Used",
                            "RiskLevel": "High",
                            "RiskScore": risk_score,
                            "Recommendation": f"Deactivate unused access key '{key_id}' for user '{username}'."
                        })
            logger.info("Completed scanning unused IAM access keys.")
            return findings
        except Exception as e:
            logger.exception("Error scanning unused IAM access keys:")
            return []
    
    def scan_root_account_mfa(self):
        """
        Check if the AWS root account has Multi-Factor Authentication (MFA) enabled.

        Retrieves the account summary and determines the MFA status. If MFA is not enabled,
        the method calculates a risk score and creates a finding with a recommendation.

        Returns:
            dict: A dictionary containing the MFA status for the root account, associated risk level,
                  risk score, and a recommendation.
        """
        if not self.iam_client:
            logger.error("IAM client not initialized.")
            return {}
        
        try:
            # Retrieve the account summary data.
            response = self.iam_client.get_account_summary()
            summary = response['SummaryMap']
            mfa_devices = summary.get('AccountMFAEnabled', 0)
            has_mfa = mfa_devices > 0
            # If MFA is not enabled, assign a critical risk level.
            risk_level = "Critical" if not has_mfa else "Low"
            compliance_violations = 3 if not has_mfa else 0
            risk_score = self.calculate_risk_score(
                exposure=risk_level,
                compliance_violations=compliance_violations,
                impact="Critical"
            )
            recommendation = (
                "Enable MFA on the root account immediately to enhance security."
                if not has_mfa else "Root account MFA is enabled."
            )
            logger.info("Completed scanning root account MFA.")
            return {
                "RootAccountMFAEnabled": has_mfa,
                "RiskLevel": risk_level,
                "RiskScore": risk_score,
                "Recommendation": recommendation
            }
        except Exception as e:
            logger.exception("Error checking root account MFA:")
            return {}
    
    def calculate_risk_level(self, actions, resources):
        """
        Determine the risk level for a policy statement based on its actions and resources.

        Args:
            actions (list): A list of actions defined in the policy statement.
            resources (list): A list of resources defined in the policy statement.

        Returns:
            str: The risk level ("Critical" if both actions and resources are wild, otherwise "High").
        """
        if '*' in actions and '*' in resources:
            return "Critical"
        return "High"

    def generate_recommendation(self, policy_name):
        """
        Generate a remediation recommendation for a given IAM policy.

        Args:
            policy_name (str): The name of the IAM policy to be remediated.

        Returns:
            str: A recommendation advising to review and restrict the policy permissions.
        """
        return f"Review and restrict the permissions defined in the policy '{policy_name}'."

    def run_all_compliance_checks(self):
        """
        Execute all IAM compliance checks and aggregate the findings.

        This method combines the results from scanning for overly permissive policies,
        unused access keys, and root account MFA status.

        Returns:
            dict: A dictionary containing compliance findings for:
                  - 'OverlyPermissivePolicies'
                  - 'UnusedAccessKeys'
                  - 'RootMFA'
        """
        logger.info("Running IAM compliance checks...")
        results = {
            "OverlyPermissivePolicies": self.scan_overly_permissive_policies(),
            "UnusedAccessKeys": self.scan_unused_access_keys(),
            "RootMFA": self.scan_root_account_mfa()
        }
        logger.info("Completed IAM compliance checks.")
        return results
