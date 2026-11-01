import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ProtectedRoute } from './routes/ProtectedRoute';
import { AppLayout } from './layouts/AppLayout';

import { LandingPage } from './pages/LandingPage';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { DashboardPage } from './pages/DashboardPage';
import { ScanUploadPage } from './pages/ScanUploadPage';
import { ScanResultsPage } from './pages/ScanResultsPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { AlertsPage } from './pages/AlertsPage';
import { ModelPerformancePage } from './pages/ModelPerformancePage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Routes */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* Protected SOC Routes */}
          <Route element={<ProtectedRoute />}>
            <Route element={<AppLayout />}>
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/scan" element={<ScanUploadPage />} />
              <Route path="/scan/results/:scanId" element={<ScanResultsPage />} />
              <Route path="/history" element={<ScanHistoryPage />} />
              <Route path="/threat-intel" element={<ThreatIntelPage />} />
              <Route path="/analytics" element={<AnalyticsPage />} />
              <Route path="/alerts" element={<AlertsPage />} />
              <Route path="/reports" element={<ReportsPage />} />
              <Route path="/model-performance" element={<ModelPerformancePage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Route>
          </Route>

          {/* Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
