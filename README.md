# Cloud Service Misconfiguration Scanner

## Overview

The **Cloud Service Misconfiguration Scanner** is a comprehensive tool designed to automatically detect, assess, and report misconfigurations across AWS cloud services. This project aims to help organizations enhance their cloud security posture by providing detailed insights into configuration issues and actionable remediation recommendations.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Technical Requirements](#technical-requirements)
- [Setup and Installation](#setup-and-installation)
- [Running the Application](#running-the-application)
- [Testing](#testing)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Automated Scanning**: Regular and compliance-based scans for misconfigurations in EC2, S3, IAM, and RDS services.
- **Compliance Checks**: Evaluate AWS configurations against standards like CIS, NIST, and PCI.
- **Risk Scoring**: Calculate risk scores for each misconfiguration, normalized to a 0-100 scale.
- **Actionable Insights**: Provide clear remediation steps for detected issues.
- **Interactive Dashboard**: A React-based user interface for viewing live monitoring data, initiating scans, and analyzing results.
- **Reporting**: Export scan results in JSON, CSV, or PDF formats for offline analysis.

## Architecture

### Backend

- **Framework**: Flask-based API.
- **Scanning Modules**:
  - **EC2**: Identifies overly permissive security groups and network ACLs.
  - **S3**: Detects public buckets, evaluates ACLs, and verifies encryption.
  - **IAM**: Checks for excessive permissions, unused credentials, and root account MFA.
  - **RDS**: Evaluates public accessibility and encryption configurations for databases.
- **Reporting**: Aggregates results and generates detailed reports.
- **Risk Scoring**: Assigns severity levels to issues using custom scoring logic.

### Frontend

- **Framework**: React with CoreUI components.
- **Features**:
  - **Live Monitoring**: Displays real-time updates of scan results.
  - **Scan Controls**: Buttons to trigger regular and compliance scans.
  - **Risk Visualization**: Circular progress bars showing aggregated risk scores.
  - **Detailed Results**: Tabular data with badges indicating risk levels.

## Technical Requirements

- Python 3.9 or higher
- Node.js 16.x or higher
- AWS CLI configured with necessary permissions
- MongoDB for storing scan results (optional, if persistence is needed)

## Setup and Installation

### Backend Setup

1. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
2. **Install the required dependencies**:
   ```bash
   pip install -r requirements.txt
4. **Set up environment variables: Create a .env file in the backend directory and define**:
   ```bash
   AWS_ACCESS_KEY_ID=your-access-key-id
   AWS_SECRET_ACCESS_KEY=your-secret-access-key
   FLASK_APP=app
   FLASK_ENV=development
6. **Run the Flask server**:
   ```bash
   flask run

### Frontend Setup

1. **Navigate to the frontend directory**:
   ```bash
   cd ../frontend
2. **Install dependencies**:
   ```bash
   npm install
4. **Set up environment variables: Create a .env file in the frontend directory and define**:
   ```bash
   REACT_APP_API_BASE_URL=http://localhost:5000
6. **Start the React development server**:
   ```bash
   npm start
### Testing

To test the backend, use `pytest`:

1. Navigate to the backend directory:
   ```bash
   cd backend
2. Run the tests
   ```bash
   pytest
