"""
Module: ec2_compliance_scanner
Description:
    Provides an implementation for scanning EC2 security groups for misconfigurations 
    and compliance issues based on predefined risk criteria. This scanner integrates
    with AWS services using boto3 to fetch security group configurations and calculates
    a risk score for each identified issue. It supports basic checks against industry 
    standards (CIS, NIST, PCI).
"""

from app.utils.aws_helpers import get_aws_client
from app.utils.logger import logger  

# Constants for risk score calculation
EXPOSURE_SCORES = {"High": 10, "Medium": 5, "Low": 1}
IMPACT_SCORES = {"High": 10, "Medium": 5, "Low": 2}
COMPLIANCE_WEIGHT = 5  
WEIGHTS = {"exposure": 0.5, "compliance": 0.3, "impact": 0.2}


class EC2ComplianceScanner:
    """
    Scanner for performing compliance checks on EC2 security groups.

    This class integrates with AWS EC2 to scan for overly permissive security group configurations,
    particularly focusing on TCP ports such as SSH (22) and RDP (3389). It calculates a risk score for
    each finding based on exposure, compliance violations, and potential impact, then provides 
    remediation recommendations.

    Attributes:
        ec2_client: boto3 client for interacting with AWS EC2 in the specified region.
    """
    
    def __init__(self, region="ap-northeast-1"):
        """
        Initialize the EC2ComplianceScanner with an AWS EC2 client.

        Args:
            region (str): The AWS region to target for scanning. Default is 'ap-northeast-1'.
        """
        self.ec2_client = get_aws_client("ec2", region)

    def calculate_risk_score(self, exposure, compliance_violations, impact):
        """
        Calculate the normalized risk score for a given configuration finding.

        The risk score is calculated using a weighted sum of exposure, compliance violation,
        and impact scores. The raw score is then normalized to a percentage.

        Args:
            exposure (str): The exposure level ('High', 'Medium', or 'Low').
            compliance_violations (int): The number of compliance violations.
            impact (str): The impact level ('High', 'Medium', or 'Low').

        Returns:
            float: The normalized risk score rounded to two decimal places.
        """
        # Retrieve numeric scores based on defined constants
        exposure_score = EXPOSURE_SCORES.get(exposure, 0)
        impact_score = IMPACT_SCORES.get(impact, 0)
        compliance_score = compliance_violations * COMPLIANCE_WEIGHT

        # Compute the raw risk score using defined weights
        raw_score = (
            WEIGHTS["exposure"] * exposure_score +
            WEIGHTS["compliance"] * compliance_score +
            WEIGHTS["impact"] * impact_score
        )
        # Normalize the score to a percentage scale (assuming 15 is the max raw score)
        normalized_score = (raw_score / 15) * 100
        return round(normalized_score, 2)

    def scan_overly_permissive_security_groups(self):
        """
        Scan EC2 security groups for overly permissive rules.

        Iterates through all the security groups in the region, checks for TCP rules with open access 
        (i.e., 0.0.0.0/0) on sensitive ports (SSH/RDP), and calculates a risk score for each finding.
        Also provides remediation recommendations based on the port configurations.

        Returns:
            list: A list of dictionaries, each representing a finding with details such as the security group ID,
                  affected ports, risk level, and recommended remediation actions.
        """
        findings = []
        try:
            # Retrieve all security groups using the AWS EC2 client
            response = self.ec2_client.describe_security_groups()
            for sg in response.get("SecurityGroups", []):
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "")
                # Iterate over each permission rule in the security group
                for permission in sg.get("IpPermissions", []):
                    protocol = permission.get("IpProtocol", "")
                    # Only consider TCP protocols for this check
                    if protocol.lower() != "tcp":
                        continue
                    
                    from_port = permission.get("FromPort")
                    to_port = permission.get("ToPort")
                    # Check each IP range for open access to the internet
                    for ip_range in permission.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp")
                        if cidr == "0.0.0.0/0":
                            # Determine the risk level based on sensitive port numbers (SSH and RDP)
                            risk_level = "High" if from_port in [22, 3389] or to_port in [22, 3389] else "Medium"
                            compliance_violations = 3  # Static number for demo purposes; can be enhanced as needed
                            exposure = "High"  # Default exposure level; could be adjusted based on additional criteria
                            
                            # Calculate risk score using the helper method
                            risk_score = self.calculate_risk_score(
                                exposure=exposure,
                                compliance_violations=compliance_violations,
                                impact=risk_level,
                            )
                            # Append a finding with necessary details and remediation recommendation
                            findings.append({
                                "SecurityGroupId": sg_id,
                                "GroupName": sg_name,
                                "FromPort": from_port,
                                "ToPort": to_port,
                                "Protocol": protocol,
                                "Issue": f"Open access on sensitive port(s) ({from_port} - {to_port})",
                                "RiskLevel": risk_level,
                                "Recommendation": self.generate_recommendation(from_port, to_port),
                                "RiskScore": risk_score,
                            })
            logger.info("Completed scanning EC2 security groups for compliance.")
            return findings
        except Exception as e:
            # Log the exception with full stack trace for debugging purposes
            logger.exception("Error scanning EC2 security groups for compliance")
            return []

    def generate_recommendation(self, from_port, to_port):
        """
        Generate remediation recommendation based on the port configuration.

        Args:
            from_port (int): Starting port number of the security group rule.
            to_port (int): Ending port number of the security group rule.

        Returns:
            str: A recommendation string advising on how to secure the identified issue.
        """
        # Provide specific remediation advice based on well-known port numbers for SSH and RDP
        if from_port == 22 or to_port == 22:
            return "Restrict SSH access to trusted IPs only."
        elif from_port == 3389 or to_port == 3389:
            return "Restrict RDP access to trusted IPs only."
        else:
            return "Ensure that sensitive ports are protected by limiting access to trusted sources."

    def run_all_compliance_checks(self):
        """
        Run the complete set of compliance checks on EC2 resources.

        Currently, this method runs the overly permissive security groups check and maps the findings
        to different compliance standards (CIS, NIST, PCI). This structure supports future extension 
        for additional compliance checks.

        Returns:
            dict: A dictionary with compliance standard keys (e.g., 'CIS', 'NIST', 'PCI')
                  and their corresponding findings.
        """
        logger.info("Running all EC2 compliance checks...")
        # Execute check for overly permissive security groups
        cis_findings = {
            "OverlyPermissiveSecurityGroups": self.scan_overly_permissive_security_groups(),
        }
        # Duplicate findings for NIST and PCI standards as a placeholder
        nist_findings = {"OverlyPermissiveSecurityGroups": cis_findings["OverlyPermissiveSecurityGroups"]}
        pci_findings = {"OverlyPermissiveSecurityGroups": cis_findings["OverlyPermissiveSecurityGroups"]}
        
        # Consolidate results for all compliance standards
        results = {
            "CIS": cis_findings,
            "NIST": nist_findings,
            "PCI": pci_findings,
        }
        logger.info("EC2 compliance checks complete.")
        return results
