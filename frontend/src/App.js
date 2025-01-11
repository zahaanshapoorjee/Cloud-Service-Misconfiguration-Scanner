import React from 'react';
import { CContainer, CRow, CCol } from '@coreui/react';
import Dashboard from './components/Dashboard'; 
import '@coreui/coreui/dist/css/coreui.min.css'; 

function App() {
  return (
    <CContainer fluid>
      <CRow className="mt-4">
      </CRow>
      <CRow>
        <CCol>
        <h1 className="dashboard-title">Cloud Misconfiguration Scanner</h1>
          <Dashboard />
        </CCol>
      </CRow>
    </CContainer>
  );
}

export default App;
