import { UserRole } from '../../types/auth.types';

export interface NavCatalogItem {
  id: number;
  label: string;
  path: string;
  group: 'Core & Posture' | 'Assessments & Auditors' | 'Intelligence & Analyzers' | 'Findings & AI Copilot' | 'Administration & Account';
  allowedRoles: UserRole[];
  readOnlyForViewer?: boolean;
}

export const NAVIGATION_CATALOG: NavCatalogItem[] = [
  {
    id: 1,
    label: 'Dashboard',
    path: '/dashboard',
    group: 'Core & Posture',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'],
  },
  {
    id: 2,
    label: 'Website Assessment',
    path: '/assessments/website',
    group: 'Assessments & Auditors',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'],
    readOnlyForViewer: true,
  },
  {
    id: 3,
    label: 'Network Assessment',
    path: '/assessments/network',
    group: 'Assessments & Auditors',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'],
    readOnlyForViewer: true,
  },
  {
    id: 4,
    label: 'Wi-Fi Security Auditor',
    path: '/auditors/wifi',
    group: 'Assessments & Auditors',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'],
    readOnlyForViewer: true,
  },
  {
    id: 18,
    label: 'Wi-Fi Password Lab',
    path: '/auditors/wifi-lab',
    group: 'Assessments & Auditors',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'],
    readOnlyForViewer: false,
  },
  {
    id: 5,
    label: 'Windows Security Auditor',
    path: '/auditors/windows',
    group: 'Assessments & Auditors',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'],
    readOnlyForViewer: true,
  },
  {
    id: 6,
    label: 'LinkGuard AI',
    path: '/intelligence/linkguard',
    group: 'Intelligence & Analyzers',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'],
  },
  {
    id: 7,
    label: 'SSL/TLS Analyzer',
    path: '/analyzers/ssl-tls',
    group: 'Intelligence & Analyzers',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'],
  },
  {
    id: 8,
    label: 'DNS Analyzer',
    path: '/analyzers/dns',
    group: 'Intelligence & Analyzers',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'],
  },
  {
    id: 9,
    label: 'Vulnerability Findings',
    path: '/findings',
    group: 'Findings & AI Copilot',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'],
    readOnlyForViewer: true,
  },
  {
    id: 10,
    label: 'AI Security Analyst',
    path: '/ai/analyst',
    group: 'Findings & AI Copilot',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST'],
  },
  {
    id: 11,
    label: 'AI Report Studio',
    path: '/reports/studio',
    group: 'Findings & AI Copilot',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST'],
  },
  {
    id: 12,
    label: 'Assessment History',
    path: '/assessments/history',
    group: 'Core & Posture',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'],
  },
  {
    id: 13,
    label: 'Reports',
    path: '/reports',
    group: 'Findings & AI Copilot',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'],
  },
  {
    id: 14,
    label: 'Integrations',
    path: '/integrations',
    group: 'Administration & Account',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST'],
  },
  {
    id: 15,
    label: 'User Management',
    path: '/admin/users',
    group: 'Administration & Account',
    allowedRoles: ['ADMIN'],
  },
  {
    id: 16,
    label: 'Settings',
    path: '/settings',
    group: 'Administration & Account',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'],
  },
  {
    id: 17,
    label: 'Account Security',
    path: '/account/security',
    group: 'Administration & Account',
    allowedRoles: ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'],
  },
];
