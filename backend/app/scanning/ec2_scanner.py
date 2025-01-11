"""
Module: ec2_scanner
Description:
    Provides a set of tools for scanning AWS EC2 resources, specifically security groups
    and network ACLs, for potential misconfigurations. The module calculates a normalized
    risk score based on exposure, compliance violations, and impact. Remediation recommendations
    are generated for insecure configurations, such as overly permissive access.
"""

from app.utils.aws_helpers import get_aws_client
from app.utils.logger import logger  

# Constants for risk score calculations
EXPOSURE_SCORES = {"High": 10, "Medium": 5, "Low": 1}
IMPACT_SCORES = {"Critical": 15, "High": 10, "Medium": 5}
COMPLIANCE_WEIGHT = 5  
WEIGHTS = {"exposure": 0.5, "compliance": 0.3, "impact": 0.2}

# Define the worst-case raw score for normalization purposes.
WORST_CASE_RAW_SCORE = 15


class EC2Scanner:
    """
    EC2Scanner performs security scans on EC2 resources including security groups and network ACLs.
    
    It calculates risk scores using a weighted formula based on exposure, compliance violations,
    and impact. The class also provides remediation recommendations based on the nature of the issue.
    """

    def __init__(self, region="ap-northeast-1"):
        """
        Initialize the EC2Scanner with an AWS EC2 client for the specified region.

        Args:
            region (str): AWS region to target for scanning. Default: 'ap-northeast-1'.
        """
        self.ec2_client = get_aws_client("ec2", region)

    def calculate_risk_score(self, exposure, compliance_violations, impact):
        """
        Calculate and normalize the risk score for a given security finding.

        Uses a weighted sum of exposure, compliance violations (multiplied by a compliance weight),
        and impact scores. The resulting raw score is normalized to a percentage.

        Args:
            exposure (str): The exposure level ('High', 'Medium', 'Low').
            compliance_violations (int): Number of compliance violations detected.
            impact (str): Impact level ('Critical', 'High', 'Medium').

        Returns:
            float: A normalized risk score rounded to two decimals.
        """
        # Map the textual levels to numerical scores using predefined constants.
        exposure_score = EXPOSURE_SCORES.get(exposure, 0)
        impact_score = IMPACT_SCORES.get(impact, 0)
        compliance_score = compliance_violations * COMPLIANCE_WEIGHT

        # Calculate the raw score based on the weighted values.
        raw_score = (
            WEIGHTS["exposure"] * exposure_score +
            WEIGHTS["compliance"] * compliance_score +
            WEIGHTS["impact"] * impact_score
        )
        # Normalize the score relative to the worst-case scenario.
        normalized_score = (raw_score / WORST_CASE_RAW_SCORE) * 100
        return round(normalized_score, 2)

    def scan_security_groups(self):
        """
        Scan EC2 security groups for overly permissive access.

        This method inspects each security group's permissions to identify rules that allow
        unrestricted access (i.e., from '0.0.0.0/0'). For each such occurrence, the risk level
        is calculated based on the port range. A risk score is then derived along with a remediation
        recommendation.

        Returns:
            list: A list of dictionaries containing details of each insecure security group rule.
        """
        # Ensure the EC2 client is properly initialized.
        if not self.ec2_client:
            logger.error("EC2 client not initialized.")
            return []

        findings = []
        try:
            # Retrieve all security groups from the AWS environment.
            response = self.ec2_client.describe_security_groups()
            for sg in response["SecurityGroups"]:
                for permission in sg.get("IpPermissions", []):
                    for ip_range in permission.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp")
                        # Check for rules that allow access from any IP.
                        if cidr == "0.0.0.0/0":
                            # Determine risk level based on port ranges.
                            risk_level = self.calculate_risk_level(
                                permission.get("FromPort"), permission.get("ToPort")
                            )
                            # Generate remediation recommendation for the identified rule.
                            recommendation = self.generate_recommendation(
                                permission.get("FromPort"), permission.get("ToPort")
                            )

                            compliance_violations = 3  # Static number for demonstration.
                            exposure = "High" if cidr == "0.0.0.0/0" else "Medium"
                            
                            # Calculate the risk score for this finding.
                            risk_score = self.calculate_risk_score(
                                exposure=exposure,
                                compliance_violations=compliance_violations,
                                impact=risk_level,
                            )

                            findings.append({
                                "SecurityGroupId": sg["GroupId"],
                                "GroupName": sg["GroupName"],
                                "IpProtocol": permission.get("IpProtocol"),
                                "FromPort": permission.get("FromPort"),
                                "ToPort": permission.get("ToPort"),
                                "CidrIp": cidr,
                                "RiskLevel": risk_level,
                                "RiskScore": risk_score,
                                "Recommendation": recommendation,
                            })
            logger.info("Completed scanning EC2 security groups.")
            return findings
        except Exception as e:
            # Log exception details to assist in debugging issues during the scan.
            logger.exception("Error scanning EC2 security groups:")
            return []

    def scan_network_acls(self):
        """
        Scan Network ACLs for entries allowing open access.

        Iterates through network ACL entries to identify those that allow ingress or egress
        from any IP address (CIDR '0.0.0.0/0'). For each insecure configuration, the risk level is 
        determined and remediation recommendations are generated.

        Returns:
            list: A list of findings with details regarding each open ACL entry.
        """
        if not self.ec2_client:
            logger.error("EC2 client not initialized.")
            return []

        findings = []
        try:
            # Retrieve all network ACLs from the AWS environment.
            response = self.ec2_client.describe_network_acls()
            for acl in response["NetworkAcls"]:
                for entry in acl.get("Entries", []):
                    # Check if the ACL entry allows traffic from any source.
                    if entry.get("CidrBlock") == "0.0.0.0/0":
                        # Calculate the risk level based on the rule action and whether it is egress.
                        risk_level = self.calculate_risk_level(
                            entry.get("RuleAction"), entry.get("Egress")
                        )
                        # Generate a tailored recommendation based on ACL specifics.
                        recommendation = self.generate_recommendation_for_acl(
                            entry.get("RuleAction"), entry.get("Egress")
                        )

                        compliance_violations = 3  # Static violation count for demonstration.
                        exposure = "High" if entry.get("CidrBlock") == "0.0.0.0/0" else "Medium"
                        
                        # Compute the risk score for the ACL entry.
                        risk_score = self.calculate_risk_score(
                            exposure=exposure,
                            compliance_violations=compliance_violations,
                            impact=risk_level,
                        )

                        findings.append({
                            "NetworkAclId": acl["NetworkAclId"],
                            "RuleNumber": entry.get("RuleNumber"),
                            "Protocol": entry.get("Protocol"),
                            "RuleAction": entry.get("RuleAction"),
                            "Egress": entry.get("Egress"),
                            "CidrBlock": entry.get("CidrBlock"),
                            "RiskLevel": risk_level,
                            "RiskScore": risk_score,
                            "Recommendation": recommendation,
                        })
            logger.info("Completed scanning Network ACLs.")
            return findings
        except Exception as e:
            # Log any exceptions encountered during the ACL scan.
            logger.exception("Error scanning Network ACLs:")
            return []

    def calculate_risk_level(self, from_port, to_port):
        """
        Determine the risk level based on port configurations or rule details.

        Args:
            from_port (int or None): The starting port of the rule.
            to_port (int or None): The ending port of the rule.

        Returns:
            str: A risk level classification ('Critical', 'High', or 'Medium').
        """
        # Critical risk if no port information is provided.
        if from_port is None and to_port is None: 
            return "Critical"
        # High risk for sensitive ports (SSH and RDP).
        if from_port == 22 or to_port == 22:
            return "High"
        elif from_port == 3389 or to_port == 3389:
            return "High"
        # Default risk level.
        else:
            return "Medium"

    def generate_recommendation(self, from_port, to_port):
        """
        Generate a remediation recommendation for a security group rule based on ports.

        Args:
            from_port (int or None): The starting port of the rule.
            to_port (int or None): The ending port of the rule.

        Returns:
            str: A recommendation to mitigate the security issue.
        """
        if from_port == 22 or to_port == 22: 
            return "Restrict SSH access to trusted IP addresses only."
        elif from_port == 3389 or to_port == 3389:  
            return "Restrict RDP access to trusted IP addresses only."
        elif from_port is None and to_port is None:  
            return "Close all open ports or restrict access to trusted IP addresses."
        else:
            return "Limit access to trusted sources only."

    def generate_recommendation_for_acl(self, rule_action, egress):
        """
        Generate a remediation recommendation for a network ACL entry based on its action and direction.

        Args:
            rule_action (str): The action of the ACL rule (e.g., 'allow' or 'deny').
            egress (bool): Indicates if the rule is for egress traffic.

        Returns:
            str: A recommendation for adjusting the ACL rule.
        """
        if rule_action == "allow" and not egress:
            return "Restrict ingress traffic to trusted IP ranges."
        elif rule_action == "allow" and egress:
            return "Restrict egress traffic to trusted destinations."
        elif rule_action == "deny":
            return "Ensure that deny rules do not conflict with organizational policies."
        else:
            return "Review the ACL rule for potential misconfigurations."
