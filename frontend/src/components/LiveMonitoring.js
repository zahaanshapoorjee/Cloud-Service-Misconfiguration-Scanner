/**
 * @module LiveMonitoring
 * @description
 * The LiveMonitoring component fetches live scan report data at regular intervals from the backend API
 * and displays it in a scrollable table format using CoreUI components.
 *
 * It:
 * - Fetches report data via the apiService.
 * - Processes the raw report into log entries.
 * - Filters out duplicate logs.
 * - Shows a spinner while loading.
 * - Displays logs with timestamp, service, description, and risk level badges.
 */

import React, { useEffect, useState } from 'react';
import {
  CTable,
  CTableBody,
  CTableRow,
  CTableHeaderCell,
  CTableDataCell,
  CTableHead,
  CBadge,
  CSpinner,
} from '@coreui/react';
import apiService from '../api/apiService';
import './LiveMonitoring.css';

const LiveMonitoring = () => {
  // State to store processed log entries.
  const [logs, setLogs] = useState([]);
  // State to indicate loading status.
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    /**
     * Fetch and process report data from the backend API.
     */
    const fetchReportData = async () => {
      try {
        const reportData = await apiService.fetchReport();
        const newLogs = processReportData(reportData);
        setLogs((prevLogs) => filterDuplicates([...newLogs, ...prevLogs]));
        setLoading(false);
      } catch (error) {
        console.error('Error fetching live monitoring data:', error);
        setLoading(false);
      }
    };

    fetchReportData();
    // Refresh the report data every 30 seconds.
    const interval = setInterval(fetchReportData, 30000);
    return () => clearInterval(interval);
  }, []);

  /**
   * Process the raw report data into an array of log entries.
   *
   * @param {Object} reportData - Report data fetched from the backend.
   * @returns {Array<Object>} Array of log objects.
   */
  const processReportData = (reportData) => {
    const newLogs = [];
    Object.entries(reportData).forEach(([service, findings]) => {
      Object.entries(findings).forEach(([category, items]) => {
        if (Array.isArray(items)) {
          items.forEach((item, index) => {
            newLogs.push({
              id: `${service}-${category}-${index}`,
              service,
              description: item?.Issue || `New issue in ${category}`,
              riskLevel: item?.RiskLevel || 'Unknown',
              timestamp: new Date().toLocaleTimeString(),
            });
          });
        } else if (typeof items === 'object') {
          newLogs.push({
            id: `${service}-${category}`,
            service,
            description: items?.Issue || `New issue in ${category}`,
            riskLevel: items?.RiskLevel || 'Unknown',
            timestamp: new Date().toLocaleTimeString(),
          });
        }
      });
    });
    return newLogs;
  };

  /**
   * Filter out duplicate logs based on a unique log ID.
   *
   * @param {Array<Object>} logs - Array of log objects.
   * @returns {Array<Object>} Array with unique log objects.
   */
  const filterDuplicates = (logs) => {
    const uniqueLogs = [];
    const seenIds = new Set();
    for (const log of logs) {
      if (!seenIds.has(log.id)) {
        uniqueLogs.push(log);
        seenIds.add(log.id);
      }
    }
    return uniqueLogs;
  };

  /**
   * Map a risk level to a corresponding badge color.
   *
   * @param {string} riskLevel - The risk level (e.g., 'Critical', 'High').
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

  return (
    <div className="live-monitoring">
      <h3 className="live-title">Live Monitoring</h3>
      {loading ? (
        <CSpinner color="primary" />
      ) : (
        <div className="scrollable-container">
          <CTable striped hover responsive style={{ borderRadius: '15px' }}>
            <CTableHead>
              <CTableRow>
                <CTableHeaderCell>Timestamp</CTableHeaderCell>
                <CTableHeaderCell>Service</CTableHeaderCell>
                <CTableHeaderCell>Description</CTableHeaderCell>
                <CTableHeaderCell>Risk Level</CTableHeaderCell>
              </CTableRow>
            </CTableHead>
            <CTableBody>
              {logs.map((log, index) => (
                <CTableRow key={log.id || index}>
                  <CTableDataCell>{log.timestamp}</CTableDataCell>
                  <CTableDataCell>{log.service}</CTableDataCell>
                  <CTableDataCell>{log.description}</CTableDataCell>
                  <CTableDataCell>
                    <CBadge color={getRiskBadge(log.riskLevel)}>
                      {log.riskLevel}
                    </CBadge>
                  </CTableDataCell>
                </CTableRow>
              ))}
            </CTableBody>
          </CTable>
        </div>
      )}
    </div>
  );
};

export default LiveMonitoring;
