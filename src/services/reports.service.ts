import { apiClient } from './apiClient';
import { ExternalImportRecord, SecurityReport } from '../types/reports.types';
import { INITIAL_EXTERNAL_IMPORTS, INITIAL_REPORTS } from '../data/seedPreviewData';

export const reportsService = {
  async listReports() {
    return apiClient.request<SecurityReport[]>(
      '/reports',
      { method: 'GET' },
      () => INITIAL_REPORTS
    );
  },

  async listImports() {
    return apiClient.request<ExternalImportRecord[]>(
      '/imports',
      { method: 'GET' },
      () => INITIAL_EXTERNAL_IMPORTS
    );
  },
};
