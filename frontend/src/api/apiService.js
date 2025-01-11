/**
 * @module apiService
 * @description
 * Provides functions to interact with the backend API for fetching reports and scan data.
 * The API base URL is configured from the environment variable REACT_APP_API_BASE_URL.
 */

import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL;

/**
 * Fetches the report from the backend API.
 *
 * @async
 * @function fetchReport
 * @returns {Promise<Object>} The report data as a JSON object.
 * @throws {Error} If the API call fails.
 */
export const fetchReport = async () => {
  try {
    const response = await axios.get(`${API_BASE_URL}/report`);
    return response.data;
  } catch (error) {
    console.error('Error fetching report:', error);
    throw error;
  }
};

/**
 * Fetches scan data from the specified endpoint.
 *
 * @async
 * @function fetchScanData
 * @param {string} endpoint - The specific scan endpoint (e.g., 'ec2', 's3', etc.).
 * @returns {Promise<Object>} The scan data as a JSON object.
 * @throws {Error} If the API call fails.
 */
export const fetchScanData = async (endpoint) => {
  try {
    const response = await axios.get(`${API_BASE_URL}/scan/${endpoint}`);
    return response.data;
  } catch (error) {
    console.error(`Error fetching ${endpoint} scan data:`, error);
    throw error;
  }
};

export default {
  fetchReport,
  fetchScanData,
};
