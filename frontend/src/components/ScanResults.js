/**
 * @module ScanResults
 * @description
 * The ScanResults component displays the scan findings in a tabular format.
 *
 * It accepts a `results` prop, which is an object where each key corresponds to a
 * particular scan category (or service) and the value is an array of findings for that category.
 * The component renders a table for each category using CoreUI components.
 */

import React from 'react';
import {
  CTable,
  CTableBody,
  CTableRow,
  CTableHeaderCell,
  CTableDataCell,
  CTableHead,
  CBadge,
} from '@coreui/react';

/**
 * ScanResults component renders scan findings in table format.
 *
 * @param {Object} props - Component properties.
 * @param {Object} props.results - An object containing scan findings categorized by type.
 * @returns {JSX.Element} Rendered ScanResults component.
 */
const ScanResults = ({ results }) => {
  /**
   * Returns the CoreUI badge color corresponding to a given risk level.
   *
   * @param {string} riskLevel - The risk level (e.g., "Critical", "High", "Medium", "Low").
   * @returns {string} The badge color string.
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
   * Renders a table for a given category of scan findings.
   *
   * @param {string} key - The name of the category.
   * @param {Array} findings - Array of findings for the given category.
   * @returns {JSX.Element} A table element representing the findings.
   */
  const renderFindings = (key, findings) => {
    if (findings.length === 0) {
      return <p>No findings for {key}.</p>;
    }

    return (
      <CTable striped hover responsive>
        <CTableHead>
          <CTableRow>
            <CTableHeaderCell>Rule Action</CTableHeaderCell>
            <CTableHeaderCell>Protocol</CTableHeaderCell>
            <CTableHeaderCell>Risk Level</CTableHeaderCell>
            <CTableHeaderCell>Recommendation</CTableHeaderCell>
          </CTableRow>
        </CTableHead>
        <CTableBody>
          {findings.map((finding, index) => (
            <CTableRow key={index}>
              <CTableDataCell>{finding.RuleAction}</CTableDataCell>
              <CTableDataCell>{finding.Protocol}</CTableDataCell>
              <CTableDataCell>
                <CBadge color={getRiskBadge(finding.RiskLevel)}>
                  {finding.RiskLevel}
                </CBadge>
              </CTableDataCell>
              <CTableDataCell>{finding.Recommendation}</CTableDataCell>
            </CTableRow>
          ))}
        </CTableBody>
      </CTable>
    );
  };

  return (
    <div className="scan-results">
      <h3>Scan Results</h3>
      {/* Iterate over each category in the results object and render the findings */}
      {Object.entries(results).map(([key, value]) => (
        <div key={key} className="result-section">
          <h4>{key}</h4>
          {Array.isArray(value) ? renderFindings(key, value) : <p>No findings.</p>}
        </div>
      ))}
    </div>
  );
};

export default ScanResults;
