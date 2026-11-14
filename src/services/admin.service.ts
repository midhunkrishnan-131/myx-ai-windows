import { apiClient } from './apiClient';
import { SecurityAuditEvent, UserProfile, UserRole } from '../types/auth.types';
import { INITIAL_AUDIT_LOGS, INITIAL_ORG_USERS } from '../data/seedPreviewData';

export const adminService = {
  async listUsers() {
    return apiClient.request<UserProfile[]>(
      '/users',
      { method: 'GET' },
      () => INITIAL_ORG_USERS
    );
  },

  async updateUserRole(userId: string, role: UserRole) {
    return apiClient.request<{ id: string; role: UserRole }>(
      `/users/${userId}/role`,
      {
        method: 'PUT',
        body: JSON.stringify({ role }),
      },
      () => ({ id: userId, role })
    );
  },

  async listAuditLogs() {
    return apiClient.request<SecurityAuditEvent[]>(
      '/audit-logs',
      { method: 'GET' },
      () => INITIAL_AUDIT_LOGS
    );
  },
};
