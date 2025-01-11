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
          <Dashboard />
        </CCol>
      </CRow>
    </CContainer>
  );
}

export default App;
