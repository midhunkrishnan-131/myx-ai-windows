import React from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { SystemStatusProvider } from './context/SystemStatusContext';
import { AppShell } from './components/layout/AppShell';
import { ProtectedRoute } from './components/layout/ProtectedRoute';

import { DashboardPage } from './pages/DashboardPage';
import { WebsiteAssessmentPage } from './pages/WebsiteAssessmentPage';
import { NetworkAssessmentPage } from './pages/NetworkAssessmentPage';
import { WifiAuditorPage } from './pages/WifiAuditorPage';
import { WindowsAuditorPage } from './pages/WindowsAuditorPage';
import { LinkGuardPage } from './pages/LinkGuardPage';
import { SslTlsAnalyzerPage } from './pages/SslTlsAnalyzerPage';
import { DnsAnalyzerPage } from './pages/DnsAnalyzerPage';
import { VulnerabilityFindingsPage } from './pages/VulnerabilityFindingsPage';
import { AiSecurityAnalystPage } from './pages/AiSecurityAnalystPage';
import { AiReportStudioPage } from './pages/AiReportStudioPage';
import { AssessmentHistoryPage } from './pages/AssessmentHistoryPage';
import { ReportsRepositoryPage } from './pages/ReportsRepositoryPage';
import { IntegrationsPage } from './pages/IntegrationsPage';
import { UserManagementPage } from './pages/UserManagementPage';
import { SettingsPage } from './pages/SettingsPage';
import { AccountSecurityPage } from './pages/AccountSecurityPage';
import { AuthPortalPage } from './pages/auth/AuthPortalPage';

export default function App() {
  return (
    <AuthProvider>
      <SystemStatusProvider>
        <BrowserRouter>
          <Routes>
            {/* Standalone Auth Flows */}
            <Route path="/login" element={<AuthPortalPage initialMode="LOGIN" />} />
            <Route path="/register" element={<AuthPortalPage initialMode="REGISTER" />} />
            <Route path="/verify-email" element={<AuthPortalPage initialMode="VERIFY_EMAIL" />} />
            <Route path="/forgot-password" element={<AuthPortalPage initialMode="FORGOT_PASSWORD" />} />
            <Route path="/reset-password" element={<AuthPortalPage initialMode="RESET_PASSWORD" />} />
            <Route path="/2fa-challenge" element={<AuthPortalPage initialMode="TOTP_CHALLENGE" />} />

            {/* 17 Main Application Views Wrapped in AppShell */}
            <Route
              path="/*"
              element={
                <AppShell>
                  <Routes>
                    <Route path="/" element={<Navigate to="/dashboard" replace />} />
                    <Route
                      path="/dashboard"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                          <DashboardPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/assessments/website"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                          <WebsiteAssessmentPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/assessments/network"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                          <NetworkAssessmentPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/auditors/wifi"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                          <WifiAuditorPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/auditors/windows"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                          <WindowsAuditorPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/intelligence/linkguard"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                          <LinkGuardPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/analyzers/ssl-tls"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                          <SslTlsAnalyzerPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/analyzers/dns"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                          <DnsAnalyzerPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/findings"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                          <VulnerabilityFindingsPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/ai/analyst"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST']}>
                          <AiSecurityAnalystPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/reports/studio"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST']}>
                          <AiReportStudioPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/assessments/history"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                          <AssessmentHistoryPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/reports"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                          <ReportsRepositoryPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/integrations"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST']}>
                          <IntegrationsPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/admin/users"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN']}>
                          <UserManagementPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/settings"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                          <SettingsPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/account/security"
                      element={
                        <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                          <AccountSecurityPage />
                        </ProtectedRoute>
                      }
                    />
                    <Route path="*" element={<Navigate to="/dashboard" replace />} />
                  </Routes>
                </AppShell>
              }
            />
          </Routes>
        </BrowserRouter>
      </SystemStatusProvider>
    </AuthProvider>
  );
}
