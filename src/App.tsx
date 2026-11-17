import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { SystemStatusProvider } from './context/SystemStatusContext';
import { AppShell } from './components/layout/AppShell';
import { ProtectedRoute } from './components/layout/ProtectedRoute';
import { ErrorBoundary } from './components/common/ErrorBoundary';

// Code-split pages with React.lazy to optimize initial bundle size, FCP, and LCP
const DashboardPage = lazy(() => import('./pages/DashboardPage').then((m) => ({ default: m.DashboardPage })));
const WebsiteAssessmentPage = lazy(() => import('./pages/WebsiteAssessmentPage').then((m) => ({ default: m.WebsiteAssessmentPage })));
const NetworkAssessmentPage = lazy(() => import('./pages/NetworkAssessmentPage').then((m) => ({ default: m.NetworkAssessmentPage })));
const WifiAuditorPage = lazy(() => import('./pages/WifiAuditorPage').then((m) => ({ default: m.WifiAuditorPage })));
const WifiPasswordLabPage = lazy(() => import('./pages/WifiPasswordLabPage').then((m) => ({ default: m.WifiPasswordLabPage })));
const WindowsAuditorPage = lazy(() => import('./pages/WindowsAuditorPage').then((m) => ({ default: m.WindowsAuditorPage })));
const LinkGuardPage = lazy(() => import('./pages/LinkGuardPage').then((m) => ({ default: m.LinkGuardPage })));
const SslTlsAnalyzerPage = lazy(() => import('./pages/SslTlsAnalyzerPage').then((m) => ({ default: m.SslTlsAnalyzerPage })));
const DnsAnalyzerPage = lazy(() => import('./pages/DnsAnalyzerPage').then((m) => ({ default: m.DnsAnalyzerPage })));
const NetworkTrustIntelligencePage = lazy(() => import('./pages/NetworkTrustIntelligencePage').then((m) => ({ default: m.NetworkTrustIntelligencePage })));
const VulnerabilityFindingsPage = lazy(() => import('./pages/VulnerabilityFindingsPage').then((m) => ({ default: m.VulnerabilityFindingsPage })));
const AiSecurityAnalystPage = lazy(() => import('./pages/AiSecurityAnalystPage').then((m) => ({ default: m.AiSecurityAnalystPage })));
const AiReportStudioPage = lazy(() => import('./pages/AiReportStudioPage').then((m) => ({ default: m.AiReportStudioPage })));
const AssessmentHistoryPage = lazy(() => import('./pages/AssessmentHistoryPage').then((m) => ({ default: m.AssessmentHistoryPage })));
const ReportsRepositoryPage = lazy(() => import('./pages/ReportsRepositoryPage').then((m) => ({ default: m.ReportsRepositoryPage })));
const IntegrationsPage = lazy(() => import('./pages/IntegrationsPage').then((m) => ({ default: m.IntegrationsPage })));
const UserManagementPage = lazy(() => import('./pages/UserManagementPage').then((m) => ({ default: m.UserManagementPage })));
const SettingsPage = lazy(() => import('./pages/SettingsPage').then((m) => ({ default: m.SettingsPage })));
const AccountSecurityPage = lazy(() => import('./pages/AccountSecurityPage').then((m) => ({ default: m.AccountSecurityPage })));
const AuthPortalPage = lazy(() => import('./pages/auth/AuthPortalPage').then((m) => ({ default: m.AuthPortalPage })));

const RouteLoadingFallback = () => (
  <div className="min-h-[60vh] flex flex-col items-center justify-center gap-3 text-zinc-400">
    <div className="w-8 h-8 border-2 border-amber-500/20 border-t-amber-400 rounded-full animate-spin" />
    <span className="text-xs font-mono tracking-wider uppercase text-zinc-500">Loading module...</span>
  </div>
);

export default function App() {
  return (
    <AuthProvider>
      <SystemStatusProvider>
        <BrowserRouter>
          <Suspense fallback={<RouteLoadingFallback />}>
            <Routes>
              {/* Standalone Auth Flows */}
              <Route path="/login" element={<AuthPortalPage initialMode="LOGIN" />} />
              <Route path="/register" element={<AuthPortalPage initialMode="REGISTER" />} />
              <Route path="/verify-email" element={<AuthPortalPage initialMode="VERIFY_EMAIL" />} />
              <Route path="/forgot-password" element={<AuthPortalPage initialMode="FORGOT_PASSWORD" />} />
              <Route path="/reset-password" element={<AuthPortalPage initialMode="RESET_PASSWORD" />} />
              <Route path="/2fa-challenge" element={<AuthPortalPage initialMode="TOTP_CHALLENGE" />} />

              {/* Main Application Views Wrapped in AppShell */}
              <Route
                path="/*"
                element={
                  <AppShell>
                    <ErrorBoundary fallbackTitle="Security Platform Navigation Error">
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
                          path="/auditors/wifi-lab"
                          element={
                            <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                              <WifiPasswordLabPage />
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
                          path="/intelligence/network-trust"
                          element={
                            <ProtectedRoute allowedRoles={['ADMIN', 'SECURITY_ANALYST', 'VIEWER']}>
                              <NetworkTrustIntelligencePage />
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
                    </ErrorBoundary>
                  </AppShell>
                }
              />
            </Routes>
          </Suspense>
        </BrowserRouter>
      </SystemStatusProvider>
    </AuthProvider>
  );
}
