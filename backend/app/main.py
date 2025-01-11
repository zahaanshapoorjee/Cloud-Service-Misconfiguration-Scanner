"""
Module: main
Description:
    Entry point for the Cloud Service Misconfiguration Scanner API.
    
    This Flask application provides several endpoints to run scans against AWS services
    (EC2, S3, IAM, RDS) for security misconfigurations and compliance issues. It also
    includes an endpoint for generating aggregate reports in various formats (JSON, CSV, PDF).
    
    The app leverages Flask-RESTful to expose API resources and Flask-CORS for Cross-Origin
    Resource Sharing. Logging is integrated to capture incoming requests and exceptions.
"""

from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from flask_cors import CORS
from app.utils.logger import logger  
from app.scanning.ec2_scanner import EC2Scanner
from app.scanning.ec2_compliance_scanner import EC2ComplianceScanner
from app.scanning.s3_scanner import S3Scanner  
from app.scanning.s3_compliance_scanner import S3ComplianceScanner
from app.scanning.iam_scanner import IAMScanner
from app.scanning.iam_compliance_scanner import IAMComplianceScanner
from app.scanning.rds_scanner import RDSScanner
from app.scanning.rds_compliance_scanner import RDSComplianceScanner
from app.reporting.report_generator import ReportGenerator 

# Initialize the Flask application and configure CORS
app = Flask(__name__)
CORS(app)
api = Api(app)

@app.before_request
def log_request_info():
    """
    Logs the HTTP method and URL for each incoming request.
    """
    logger.info(f"Incoming request: {request.method} {request.url}")

@app.errorhandler(Exception)
def handle_exception(e):
    """
    Global error handler for unhandled exceptions.
    
    Logs the exception and returns a JSON error response with a 500 status code.
    
    Args:
        e (Exception): The exception that occurred.
    
    Returns:
        tuple: A JSON response containing the error message and an HTTP 500 status code.
    """
    logger.exception("Unhandled exception occurred:")
    return jsonify({"error": str(e)}), 500

@app.route('/')
def home():
    """
    Home endpoint that returns a welcome message.
    
    Returns:
        JSON: A message indicating that this is the Cloud Service Misconfiguration Scanner API.
    """
    return jsonify({"message": "Cloud Service Misconfiguration Scanner API"})

class EC2Scan(Resource):
    """
    API Resource for performing a basic EC2 scan.
    
    This resource invokes methods to scan EC2 Security Groups and Network ACLs,
    and returns the scan results as JSON.
    """
    def get(self):
        scanner = EC2Scanner(region='ap-northeast-1')
        sg_findings = scanner.scan_security_groups()
        acl_findings = scanner.scan_network_acls()
        logger.info("EC2 scan completed successfully.")
        return jsonify({
            "EC2_Security_Groups": sg_findings,
            "Network_ACLs": acl_findings
        })

class EC2ComplianceScan(Resource):
    """
    API Resource for performing an EC2 compliance scan.
    
    This resource runs all compliance checks for EC2 and returns the findings.
    """
    def get(self):
        scanner = EC2ComplianceScanner(region='ap-northeast-1')
        compliance_findings = scanner.run_all_compliance_checks()
        logger.info("EC2 compliance scan completed successfully.")
        return jsonify({"EC2_Compliance": compliance_findings})

class S3Scan(Resource):
    """
    API Resource for performing a basic S3 scan.
    
    Invokes the S3Scanner to check for public access issues in S3 buckets.
    """
    def get(self):
        scanner = S3Scanner(region='ap-northeast-1')
        findings = scanner.scan_buckets_public_access()
        logger.info("S3 scan completed successfully.")
        return jsonify({"S3_Public_Buckets": findings})

class S3ComplianceScan(Resource):
    """
    API Resource for performing an S3 compliance scan.
    
    Runs all compliance checks for S3 buckets (e.g., encryption, logging, public access blocks)
    and returns the findings.
    """
    def get(self):
        scanner = S3ComplianceScanner(region='ap-northeast-1')
        compliance_findings = scanner.run_all_compliance_checks()
        logger.info("S3 compliance scan completed successfully.")
        return jsonify({"S3_Compliance": compliance_findings})

class IAMScan(Resource):
    """
    API Resource for performing a basic IAM scan.
    
    Runs scans for overly permissive IAM policies, unused access keys, and checks for root account MFA.
    """
    def get(self):
        scanner = IAMScanner(region='ap-northeast-1')
        permissive_policies = scanner.scan_overly_permissive_policies()
        unused_keys = scanner.scan_unused_access_keys()
        root_mfa = scanner.scan_root_account_mfa()
        logger.info("IAM scan completed successfully.")
        return jsonify({
            "IAM_Permissive_Policies": permissive_policies,
            "IAM_Unused_Access_Keys": unused_keys,
            "IAM_Root_Account_MFA": root_mfa
        })

class IAMComplianceScan(Resource):
    """
    API Resource for performing an IAM compliance scan.
    
    Runs all compliance checks for IAM configurations and returns the results.
    """
    def get(self):
        scanner = IAMComplianceScanner(region='ap-northeast-1')
        compliance_findings = scanner.run_all_compliance_checks()
        logger.info("IAM compliance scan completed successfully.")
        return jsonify({"IAM_Compliance": compliance_findings})

class RDSScan(Resource):
    """
    API Resource for performing a basic RDS scan.
    
    Checks for unencrypted databases, publicly accessible RDS instances, and issues with DB parameter groups.
    """
    def get(self):
        scanner = RDSScanner(region='ap-northeast-1')
        unencrypted_dbs = scanner.scan_unencrypted_databases()
        public_dbs = scanner.scan_public_accessible_databases()
        db_parameter_groups = scanner.scan_db_parameter_groups()
        logger.info("RDS scan completed successfully.")
        return jsonify({
            "RDS_Unencrypted_Databases": unencrypted_dbs,
            "RDS_Public_Access_Databases": public_dbs,
            "RDS_DB_Parameter_Groups_Issues": db_parameter_groups
        })

class RDSComplianceScan(Resource):
    """
    API Resource for performing an RDS compliance scan.
    
    Runs all compliance checks for RDS and returns the findings.
    """
    def get(self):
        scanner = RDSComplianceScanner(region='ap-northeast-1')
        compliance_findings = scanner.run_all_compliance_checks()
        logger.info("RDS compliance scan completed successfully.")
        return jsonify({"RDS_Compliance": compliance_findings})

@app.route('/report', methods=['GET'])
def generate_report():
    """
    Endpoint to generate a comprehensive report from all scan results.
    
    This endpoint runs scans across EC2, S3, IAM, and RDS, aggregates the results, and then
    generates a report in the specified format (json, csv, or pdf). The format is determined by
    the 'format' query parameter. If the format is 'pdf', the report is returned as binary data
    with the appropriate Content-Type.
    
    Returns:
        JSON or binary data: The generated report in the specified format.
    """
    # Collect scan results from all scanners
    ec2_scanner = EC2Scanner(region='ap-northeast-1')
    s3_scanner = S3Scanner(region='ap-northeast-1')
    iam_scanner = IAMScanner(region='ap-northeast-1')
    rds_scanner = RDSScanner(region='ap-northeast-1')

    scan_results = {
        "EC2": {
            "SecurityGroups": ec2_scanner.scan_security_groups(),
            "NetworkACLs": ec2_scanner.scan_network_acls(),
        },
        "S3": {
            "PublicBuckets": s3_scanner.scan_buckets_public_access(),
        },
        "IAM": {
            "PermissivePolicies": iam_scanner.scan_overly_permissive_policies(),
            "UnusedKeys": iam_scanner.scan_unused_access_keys(),
            "RootMFA": iam_scanner.scan_root_account_mfa(),
        },
        "RDS": {
            "UnencryptedInstances": rds_scanner.scan_unencrypted_databases(),
            "PublicInstances": rds_scanner.scan_public_accessible_databases(),
            "ParameterGroupIssues": rds_scanner.scan_db_parameter_groups(),
        },
    }

    # Determine the format of the report from the request query parameters, default to JSON.
    format = request.args.get('format', 'json')

    # Generate the report using the ReportGenerator class.
    generator = ReportGenerator(scan_results)
    try:
        report = generator.generate_report(format=format)
        if format == "json":
            return jsonify(report)
        elif format == "csv":
            # CSV reports are returned as a dictionary mapping services to CSV strings.
            return jsonify(report)
        elif format == "pdf":
            return report, 200, {'Content-Type': 'application/pdf'}
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Add API resource endpoints for each scanning functionality.
api.add_resource(EC2Scan, '/scan/ec2')
api.add_resource(EC2ComplianceScan, '/scan/ec2/compliance')
api.add_resource(S3Scan, '/scan/s3')
api.add_resource(S3ComplianceScan, '/scan/s3/compliance')
api.add_resource(IAMScan, '/scan/iam')
api.add_resource(IAMComplianceScan, '/scan/iam/compliance')
api.add_resource(RDSScan, '/scan/rds')
api.add_resource(RDSComplianceScan, '/scan/rds/compliance')

# Run the Flask development server if this script is executed directly.
if __name__ == '__main__':
    app.run(debug=True)
