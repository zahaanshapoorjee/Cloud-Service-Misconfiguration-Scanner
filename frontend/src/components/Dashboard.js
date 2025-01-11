/**
 * @module Dashboard
 * @description
 * The Dashboard component provides a user interface for running scans on AWS services (EC2, S3, IAM, RDS),
 * displaying live monitoring data as well as scan results. It leverages CoreUI components for layout and design,
 * and integrates with the API service to fetch scan data. Additionally, it computes and displays an aggregated
 * risk score for each service using circular progress indicators with tooltips.
 */

import React, { useState } from 'react';
import {
  CCard,
  CCardBody,
  CCardHeader,
  CButton,
  CSpinner,
  CBadge,
  CRow,
} from '@coreui/react';
import apiService from '../api/apiService';
import './Dashboard.css';
import LiveMonitoring from './LiveMonitoring'; 
import { CircularProgressbar, buildStyles } from 'react-circular-progressbar';
import 'react-circular-progressbar/dist/styles.css';
import { Tooltip } from 'react-tooltip'; 
import 'react-tooltip/dist/react-tooltip.css'; 
import { MdError, MdWarning, MdInfo, MdCheckCircle } from 'react-icons/md';

const Dashboard = () => {
  // State for handling loading status, fetched results, and current service being scanned.
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState({});
  const [currentService, setCurrentService] = useState(null);

  /**
   * Triggers a scan for the specified service and scan type.
   *
   * @async
   * @function handleScan
   * @param {string} service - The AWS service to scan (e.g., 'EC2', 'S3', etc.).
   * @param {string} scanType - The type of scan to run: 'regular' or 'compliance'.
   */
  const handleScan = async (service, scanType) => {
    try {
      setLoading(true);
      setCurrentService(service);
      // Determine endpoint based on scan type.
      const endpoint =
        scanType === 'regular'
          ? service.toLowerCase()
          : `${service.toLowerCase()}/compliance`;
      const data = await apiService.fetchScanData(endpoint);
      // Merge new scan data into existing results.
      setResults((prevResults) => ({
        ...prevResults,
        [service]: data,
      }));
    } catch (error) {
      console.error(`Error running ${scanType} scan for ${service}:`, error);
    } finally {
      setLoading(false);
      setCurrentService(null);
    }
  };

  /**
   * Maps a risk level string to a CoreUI badge color.
   *
   * @function getRiskBadge
   * @param {string} riskLevel - The risk level ('Critical', 'High', 'Medium', or 'Low').
   * @returns {string} The corresponding badge color.
   */
  const getRiskBadge = (riskLevel) => {
    switch (riskLevel) {
      case 'Critical':
        return 'danger';
      case 'High':
        return 'warning';
      case 'Medium':
        return 'info';
      case 'Low':
        return 'success';
      default:
        return 'secondary';
    }
  };

  /**
   * Renders scan results for EC2 service.
   *
   * @function renderEC2Scan
   * @param {Object} data - The scan data for EC2.
   * @returns {JSX.Element} The rendered EC2 scan findings.
   */
  const renderEC2Scan = (data) => {
    if (!data) return <p>No EC2 findings available.</p>;
  
    return (
      <div className="results-section">
        {data.EC2_Security_Groups && (
          <div className="findings-table">
            <h5>Security Groups</h5>
            {data.EC2_Security_Groups.map((group, index) => (
              <div key={index} className="finding-item">
                <div>
                  <strong>Group Name:</strong> {group.GroupName}
                </div>
                <div>
                  <strong>Port Range:</strong> {group.FromPort} - {group.ToPort}
                </div>
                <div>
                  <strong>Protocol:</strong> {group.IpProtocol}
                </div>
                <div>
                  <strong>Risk Level:</strong>{' '}
                  <CBadge color={getRiskBadge(group.RiskLevel)}>
                    {group.RiskLevel}
                  </CBadge>
                </div>
                <div>
                  <strong>Recommendation:</strong> {group.Recommendation}
                </div>
              </div>
            ))}
          </div>
        )}
  
        {data.Network_ACLs && (
          <div className="findings-table">
            <h5>Network ACLs</h5>
            {data.Network_ACLs.map((acl, index) => (
              <div key={index} className="finding-item">
                <div>
                  <strong>Network ACL ID:</strong> {acl.NetworkAclId}
                </div>
                <div>
                  <strong>Rule Number:</strong> {acl.RuleNumber}
                </div>
                <div>
                  <strong>Direction:</strong> {acl.Egress ? 'Egress' : 'Ingress'}
                </div>
                <div>
                  <strong>Protocol:</strong> {acl.Protocol === '-1' ? 'All' : acl.Protocol}
                </div>
                <div>
                  <strong>Rule Action:</strong> {acl.RuleAction}
                </div>
                <div>
                  <strong>Risk Level:</strong>{' '}
                  <CBadge color={getRiskBadge(acl.RiskLevel)}>
                    {acl.RiskLevel}
                  </CBadge>
                </div>
                <div>
                  <strong>Recommendation:</strong> {acl.Recommendation}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  /**
   * Renders scan results for S3 service.
   *
   * @function renderS3Scan
   * @param {Object} data - The scan data for S3.
   * @returns {JSX.Element} The rendered S3 scan findings.
   */
  const renderS3Scan = (data) => {
    if (!data) return <p>No S3 findings available.</p>;
  
    return (
      <div className="results-section">
        {data.S3_Public_Buckets && (
          <div className="findings-table">
            <h5>Public Buckets</h5>
            {data.S3_Public_Buckets.map((bucket, index) => (
              <div key={index} className="finding-item">
                <div>
                  <strong>Bucket Name:</strong> {bucket.BucketName}
                </div>
                <div>
                  <strong>Issue:</strong> {bucket.Issue}
                </div>
                <div>
                  <strong>Risk Level:</strong>{' '}
                  <CBadge color={getRiskBadge(bucket.RiskLevel)}>
                    {bucket.RiskLevel}
                  </CBadge>
                </div>
                <div>
                  <strong>Recommendation:</strong> {bucket.Recommendation}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  /**
   * Renders scan results for IAM service.
   *
   * @function renderIAMScan
   * @param {Object} data - The scan data for IAM.
   * @returns {JSX.Element} The rendered IAM scan findings.
   */
  const renderIAMScan = (data) => {
    if (!data) return <p>No IAM findings available.</p>;
  
    return (
      <div className="results-section">
        {data.IAM_Root_Account_MFA && (
          <div className="findings-table">
            <h5>Root Account MFA</h5>
            <div className="finding-item">
              <div>
                <strong>Issue:</strong> Root account does not have MFA enabled.
              </div>
              <div>
                <strong>Risk Level:</strong>{' '}
                <CBadge color={getRiskBadge(data.IAM_Root_Account_MFA.RiskLevel)}>
                  {data.IAM_Root_Account_MFA.RiskLevel}
                </CBadge>
              </div>
              <div>
                <strong>Recommendation:</strong> {data.IAM_Root_Account_MFA.Recommendation}
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  /**
   * Renders scan results for RDS service.
   *
   * @function renderRDSScan
   * @param {Object} data - The scan data for RDS.
   * @returns {JSX.Element} The rendered RDS scan findings.
   */
  const renderRDSScan = (data) => {
    if (!data) return <p>No RDS findings available.</p>;
  
    return (
      <div className="results-section">
        {data.RDS_Public_Access_Databases.length > 0 && (
          <div className="findings-table">
            <h5>Public Access Databases</h5>
            {data.RDS_Public_Access_Databases.map((db, index) => (
              <div key={index} className="finding-item">
                <div>
                  <strong>DB Instance Identifier:</strong> {db.DBInstanceIdentifier}
                </div>
                <div>
                  <strong>Publicly Accessible:</strong> {db.PubliclyAccessible ? 'Yes' : 'No'}
                </div>
                <div>
                  <strong>Risk Level:</strong>{' '}
                  <CBadge color={getRiskBadge(db.RiskLevel)}>
                    {db.RiskLevel}
                  </CBadge>
                </div>
                <div>
                  <strong>Recommendation:</strong> {db.Recommendation}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  /**
   * Renders S3 compliance findings by combining results across multiple compliance standards.
   *
   * @function renderS3Compliance
   * @param {Object} data - The S3 compliance scan data.
   * @returns {JSX.Element} The rendered S3 compliance findings.
   */
  const renderS3Compliance = (data) => {
    if (!data) return <p>No S3 compliance findings available.</p>;
  
    // Combine findings from different compliance standards (e.g., CIS, NIST, PCI)
    const combinedFindings = Object.entries(data).reduce((acc, [standard, findings]) => {
      if (findings) {
        Object.entries(findings).forEach(([category, categoryFindings]) => {
          if (Array.isArray(categoryFindings)) {
            categoryFindings.forEach((finding) => {
              const key = finding.BucketName;
              if (!acc[key]) {
                acc[key] = { ...finding, Standards: [standard] };
              } else if (!acc[key].Standards.includes(standard)) {
                acc[key].Standards.push(standard);
              }
            });
          }
        });
      }
      return acc;
    }, {});
  
    return (
      <div className="results-section">
        <h5>S3 Compliance Findings</h5>
        <div className="findings-table">
          {Object.values(combinedFindings).map((finding, index) => (
            <div key={index} className="finding-item">
              <div>
                <strong>Bucket Name:</strong> {finding.BucketName}
              </div>
              <div>
                <strong>Issue:</strong> {finding.Issue}
              </div>
              <div>
                <strong>Risk Level:</strong>{' '}
                <CBadge color={getRiskBadge(finding.RiskLevel)}>
                  {finding.RiskLevel}
                </CBadge>
              </div>
              <div>
                <strong>Recommendation:</strong> {finding.Recommendation}
              </div>
              <div>
                <strong>Applies to Standards:</strong> {finding.Standards.join(", ")}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  /**
   * Renders EC2 compliance findings by combining data from multiple compliance frameworks.
   *
   * @function renderEC2Compliance
   * @param {Object} data - The EC2 compliance scan data.
   * @returns {JSX.Element} The rendered EC2 compliance findings.
   */
  const renderEC2Compliance = (data) => {
    console.log("EC2 Compliance Data:", data); // Debug log
    if (!data || typeof data !== "object") {
      return <p>No EC2 compliance findings available.</p>;
    }
  
    const combinedFindings = {};
  
    // Combine findings from CIS, NIST, and PCI
    ["CIS", "NIST", "PCI"].forEach((standard) => {
      if (data[standard]?.OverlyPermissiveSecurityGroups) {
        data[standard].OverlyPermissiveSecurityGroups.forEach((finding) => {
          const key = `${finding.GroupName}-${finding.FromPort}-${finding.ToPort}`;
          if (!combinedFindings[key]) {
            combinedFindings[key] = { ...finding, Standards: [standard] };
          } else if (!combinedFindings[key].Standards.includes(standard)) {
            combinedFindings[key].Standards.push(standard);
          }
        });
      }
    });
  
    return (
      <div className="results-section">
        <h5>Overly Permissive Security Groups</h5>
        <div className="findings-table">
          {Object.values(combinedFindings).map((finding, index) => (
            <div key={index} className="finding-item">
              <div>
                <strong>Group Name:</strong> {finding.GroupName}
              </div>
              <div>
                <strong>Port Range:</strong> {finding.FromPort} - {finding.ToPort}
              </div>
              <div>
                <strong>Protocol:</strong> {finding.Protocol}
              </div>
              <div>
                <strong>Risk Level:</strong>{' '}
                <CBadge color={getRiskBadge(finding.RiskLevel)}>
                  {finding.RiskLevel}
                </CBadge>
              </div>
              <div>
                <strong>Recommendation:</strong> {finding.Recommendation}
              </div>
              <div>
                <strong>Applies to Standards:</strong> {finding.Standards.join(", ")}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  /**
   * Renders IAM compliance findings by combining data from multiple compliance frameworks.
   *
   * @function renderIAMCompliance
   * @param {Object} data - The IAM compliance scan data.
   * @returns {JSX.Element} The rendered IAM compliance findings.
   */
  const renderIAMCompliance = (data) => {
    console.log("IAM Compliance Data:", data); // Debug log
    if (!data || typeof data !== "object") {
      return <p>No IAM compliance findings available.</p>;
    }
  
    const combinedFindings = [];
  
    // Combine findings from CIS, NIST, and PCI for root MFA.
    ["CIS", "NIST", "PCI"].forEach((standard) => {
      if (data[standard]?.RootMFA) {
        data[standard].RootMFA.forEach((finding) => {
          const existing = combinedFindings.find((f) => f.Issue === finding.Issue);
          if (existing) {
            existing.Standards.push(standard);
          } else {
            combinedFindings.push({ ...finding, Standards: [standard] });
          }
        });
      }
    });
  
    return (
      <div className="results-section">
        <h5>IAM Compliance Findings</h5>
        <div className="findings-table">
          {combinedFindings.map((finding, index) => (
            <div key={index} className="finding-item">
              <div>
                <strong>Issue:</strong> {finding.Issue}
              </div>
              <div>
                <strong>Risk Level:</strong>{' '}
                <CBadge color={getRiskBadge(finding.RiskLevel)}>
                  {finding.RiskLevel}
                </CBadge>
              </div>
              <div>
                <strong>Recommendation:</strong> {finding.Recommendation}
              </div>
              <div>
                <strong>Applies to Standards:</strong> {finding.Standards.join(", ")}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  /**
   * Renders RDS compliance findings by combining data from multiple compliance frameworks.
   *
   * @function renderRDSCompliance
   * @param {Object} data - The RDS compliance scan data.
   * @returns {JSX.Element} The rendered RDS compliance findings.
   */
  const renderRDSCompliance = (data) => {
    console.log("RDS Compliance Data:", data); // Debug log
    if (!data || typeof data !== "object") {
      return <p>No RDS compliance findings available.</p>;
    }
  
    const combinedFindings = {};
  
    // Combine findings from CIS, NIST, and PCI for public RDS instances.
    ["CIS", "NIST", "PCI"].forEach((standard) => {
      if (data[standard]?.PublicInstances) {
        data[standard].PublicInstances.forEach((finding) => {
          const key = finding.DBInstanceIdentifier;
          if (!combinedFindings[key]) {
            combinedFindings[key] = { ...finding, Standards: [standard] };
          } else if (!combinedFindings[key].Standards.includes(standard)) {
            combinedFindings[key].Standards.push(standard);
          }
        });
      }
    });
  
    return (
      <div className="results-section">
        <h5>Publicly Accessible Databases</h5>
        <div className="findings-table">
          {Object.values(combinedFindings).map((finding, index) => (
            <div key={index} className="finding-item">
              <div>
                <strong>DB Instance Identifier:</strong> {finding.DBInstanceIdentifier}
              </div>
              <div>
                <strong>Issue:</strong> {finding.Issue}
              </div>
              <div>
                <strong>Risk Level:</strong>{' '}
                <CBadge color={getRiskBadge(finding.RiskLevel)}>
                  {finding.RiskLevel}
                </CBadge>
              </div>
              <div>
                <strong>Recommendation:</strong> {finding.Recommendation}
              </div>
              <div>
                <strong>Applies to Standards:</strong> {finding.Standards.join(", ")}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  /**
   * Renders the appropriate scan results based on the provided service.
   *
   * @function renderResults
   * @param {string} service - The AWS service (EC2, S3, IAM, RDS).
   * @returns {JSX.Element} The rendered results or a message if no data is available.
   */
  const renderResults = (service) => {
    const data = results[service];
    if (!data) return <p>Run a scan to view misconfigurations in {service}.</p>;
  
    const isComplianceScan = Object.keys(data).some((key) =>
      key.includes("Compliance")
    );
  
    switch (service) {
      case "EC2":
        return isComplianceScan
          ? renderEC2Compliance(data.EC2_Compliance)
          : renderEC2Scan(data);
      case "S3":
        return isComplianceScan
          ? renderS3Compliance(data.S3_Compliance)
          : renderS3Scan(data);
      case "IAM":
        return isComplianceScan
          ? renderIAMCompliance(data.IAM_Compliance)
          : renderIAMScan(data);
      case "RDS":
        return isComplianceScan
          ? renderRDSCompliance(data.RDS_Compliance)
          : renderRDSScan(data);
      default:
        return <p>Unknown service: {service}</p>;
    }
  };

  /**
   * Recursively extracts all numeric risk scores from the provided data.
   *
   * @function extractRiskScores
   * @param {any} data - The data structure containing risk scores.
   * @returns {number[]} An array of numeric risk scores.
   */
  const extractRiskScores = (data) => {
    let scores = [];
    if (Array.isArray(data)) {
      data.forEach((item) => {
        if (
          item.RiskScore !== undefined &&
          typeof item.RiskScore === "number"
        ) {
          scores.push(item.RiskScore);
        }
        // Recursively extract from nested objects/arrays.
        if (typeof item === "object" && item !== null) {
          scores = scores.concat(extractRiskScores(item));
        }
      });
    } else if (typeof data === "object" && data !== null) {
      Object.values(data).forEach((value) => {
        scores = scores.concat(extractRiskScores(value));
      });
    }
    return scores;
  };

  /**
   * Computes the aggregated risk score (average) from all extracted risk scores.
   *
   * @function computeAggregatedRiskScore
   * @param {any} data - The data structure containing risk scores.
   * @returns {string|null} The average risk score (as a string rounded to two decimals), or null if no scores are found.
   */
  const computeAggregatedRiskScore = (data) => {
    const scores = extractRiskScores(data);
    if (scores.length === 0) return null;
    const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
    return avg.toFixed(2); // Round to two decimals
  };

  /**
   * Renders a circular aggregated risk score along with a tooltip that describes risk thresholds.
   *
   * @function renderAggregatedRiskScore
   * @param {string} service - The AWS service for which to display the aggregated risk score.
   * @returns {JSX.Element|null} A circular progress bar displaying the aggregated risk score, or null if not available.
   */
  const renderAggregatedRiskScore = (service) => {
    const data = results[service];
    const aggregatedScore = computeAggregatedRiskScore(data);
  
    if (aggregatedScore) {
      let pathColor = "#6c757d"; // Default gray
      let IconComponent = MdInfo; // Default icon
      const score = parseFloat(aggregatedScore);
  
      // Adjust color and icon based on score thresholds.
      if (score >= 70) {
        pathColor = "#dc3545"; // Critical (red)
        IconComponent = MdError;
      } else if (score >= 40) {
        pathColor = "#ffc107"; // High (orange)
        IconComponent = MdWarning;
      } else if (score >= 20) {
        pathColor = "#17a2b8"; // Medium (blue)
        IconComponent = MdInfo;
      } else {
        pathColor = "#28a745"; // Low (green)
        IconComponent = MdCheckCircle;
      }
  
      // Tooltip explaining aggregated risk score thresholds.
      const tooltipText = `Aggregated Risk Score (average of all findings)
• 0-19: Low risk  
• 20-39: Medium risk  
• 40-69: High risk  
• 70-100: Critical risk`;
  
      return (
        <div>
          <div
            className="aggregated-risk-container"
            data-tooltip-id={`${service}-tooltip`}
            data-tooltip-content={tooltipText}
            style={{ width: "60px", height: "60px", marginRight: "10px" }}
          >
            <div style={{ position: "relative", width: "60px", height: "60px" }}>
              <CircularProgressbar
                value={aggregatedScore}
                text={`${aggregatedScore}`}
                styles={buildStyles({
                  textColor: pathColor,
                  pathColor: pathColor,
                  trailColor: "#d6d6d6",
                  textSize: "28px",
                  transition: "stroke-dashoffset 0.5s ease 0s",
                })}
              />
              {/* Overlay the icon */}
              <div
                style={{
                  position: "absolute",
                  top: "0",
                  right: "0",
                  transform: "translate(25%, -25%)",
                  backgroundColor: "white",
                  borderRadius: "50%",
                  padding: "2px",
                }}
              >
                <IconComponent color={pathColor} size={18} />
              </div>
            </div>
          </div>
          <Tooltip id={`${service}-tooltip`} place="top" effect="solid" multiline={true} />
        </div>
      );
    }
    return null;
  };

  return (
    <div className="dashboard-container">
      <h1 className="dashboard-title">Cloud Misconfiguration Scanner</h1>
      <div className="live-monitoring-section">
        <LiveMonitoring />
      </div>
      <h3 style={{ textAlign: "center" }}>Scan AWS Services</h3>

      <CRow className="service-row" style={{ margin: "20px" }}>
        {["EC2", "S3", "IAM", "RDS"].map((service) => (
          <CCard className="service-card full-width" key={service}>
            <CCardHeader className="service-header">
              <div className="header-content">
                <h4 style={{ margin: 0 }}>{service}</h4>
              </div>
              <div className="button-group">
                <CButton
                  color="primary"
                  onClick={() => handleScan(service, "regular")}
                  disabled={loading && currentService === service}
                >
                  {loading && currentService === service ? (
                    <CSpinner size="sm" />
                  ) : (
                    "Run Regular Scan"
                  )}
                </CButton>
                <CButton
                  color="info"
                  onClick={() => handleScan(service, "compliance")}
                  disabled={loading && currentService === service}
                >
                  {loading && currentService === service ? (
                    <CSpinner size="sm" />
                  ) : (
                    "Run Compliance Scan"
                  )}
                </CButton>
                {/* Render aggregated risk score if available */}
                {results[service] && renderAggregatedRiskScore(service)}
              </div>
            </CCardHeader>
            <CCardBody>{renderResults(service)}</CCardBody>
          </CCard>
        ))}
      </CRow>
    </div>
  );
};

export default Dashboard;
