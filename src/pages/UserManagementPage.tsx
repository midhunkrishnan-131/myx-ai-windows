import React, { useState } from 'react';
import { Users, Shield, Search } from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { useAuth } from '../hooks/useAuth';
import { UserRole } from '../types/auth.types';
import { Card } from '../components/ui/Card';
import { StatusBadge } from '../components/ui/StatusBadge';
import { Button } from '../components/ui/Button';

export const UserManagementPage: React.FC = () => {
  const { orgUsers, updateOrgUserRole, toggleOrgUserActive, auditLogs } = useSystemStatus();
  const { user } = useAuth();
  const [auditSearch, setAuditSearch] = useState('');

  const filteredLogs = auditLogs.filter(
    (log) =>
      !auditSearch.trim() ||
      log.action.toLowerCase().includes(auditSearch.toLowerCase()) ||
      log.actor_email.toLowerCase().includes(auditSearch.toLowerCase()) ||
      log.event_category.toLowerCase().includes(auditSearch.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
            Organization User Directory, RBAC & Immutable Audit Trail
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Restricted to ADMIN role · Manage ADMIN, SECURITY_ANALYST, and VIEWER roles, TOTP 2FA
            status, and append-only audit logs
          </p>
        </div>
        <StatusBadge status="ADMIN ONLY" />
      </div>

      {/* Organization Users Table */}
      <Card
        title={`Organization Members (${orgUsers.length})`}
        subtitle="Tenant: MYX Defense Operations Lab (org-myx-enterprise-01)"
        noPadding
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-[#101318] border-b border-[#29313B] text-[11px] font-medium text-[#A7B0BC]">
                <th className="py-3 px-4">User / Email</th>
                <th className="py-3 px-4">Job Title</th>
                <th className="py-3 px-4">RBAC Role</th>
                <th className="py-3 px-4">TOTP 2FA</th>
                <th className="py-3 px-4">Account Status</th>
                <th className="py-3 px-4">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#29313B] text-xs">
              {orgUsers.map((member) => (
                <tr key={member.id} className="hover:bg-[#1B222B]">
                  <td className="py-3 px-4">
                    <div className="font-semibold text-[#F5F7FA]">{member.full_name}</div>
                    <div className="font-mono text-[11px] text-[#737E8C]">{member.email}</div>
                  </td>
                  <td className="py-3 px-4 text-[#A7B0BC]">{member.job_title}</td>
                  <td className="py-3 px-4">
                    <select
                      aria-label={`Assign role for ${member.full_name}`}
                      value={member.role}
                      onChange={(e) =>
                        updateOrgUserRole(
                          member.id,
                          e.target.value as UserRole,
                          user?.email || 'midhun.krishnan@myx-security.io'
                        )
                      }
                      className="px-2.5 py-1 bg-[#080A0D] border border-[#29313B] rounded text-xs font-mono text-[#F5F7FA]"
                    >
                      <option value="ADMIN">ADMIN</option>
                      <option value="SECURITY_ANALYST">SECURITY_ANALYST</option>
                      <option value="VIEWER">VIEWER</option>
                    </select>
                  </td>
                  <td className="py-3 px-4">
                    <StatusBadge
                      status={member.totp_enabled ? '2FA VERIFIED' : '2FA NOT ENROLLED'}
                    />
                  </td>
                  <td className="py-3 px-4">
                    <StatusBadge status={member.is_active ? 'ACTIVE' : 'SUSPENDED'} />
                  </td>
                  <td className="py-3 px-4">
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() =>
                        toggleOrgUserActive(
                          member.id,
                          user?.email || 'midhun.krishnan@myx-security.io'
                        )
                      }
                    >
                      {member.is_active ? 'Suspend' : 'Reactivate'}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Immutable Organization Security Audit Logs */}
      <Card
        title="Immutable Organization Security Audit Trail (audit_logs)"
        subtitle="Append-only ledger recording AUTH, 2FA, TARGET_AUTH, ASSESSMENT, AGENT, FINDING, REPORT, INTEGRATION & RBAC events"
        noPadding
        headerAction={
          <div className="flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-[#737E8C]" />
            <input
              type="text"
              placeholder="Filter action or actor..."
              value={auditSearch}
              onChange={(e) => setAuditSearch(e.target.value)}
              className="px-2.5 py-1 bg-[#080A0D] border border-[#29313B] rounded text-xs text-[#F5F7FA]"
            />
          </div>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-[#101318] border-b border-[#29313B] text-[11px] font-medium text-[#A7B0BC]">
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Actor & Role</th>
                <th className="py-3 px-4">Resource</th>
                <th className="py-3 px-4">Metadata</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#29313B] text-xs font-mono">
              {filteredLogs.map((log) => (
                <tr key={log.id} className="hover:bg-[#1B222B]">
                  <td className="py-3 px-4 text-[#A7B0BC] whitespace-nowrap">{log.created_at}</td>
                  <td className="py-3 px-4 text-[#38BDF8]">{log.event_category}</td>
                  <td className="py-3 px-4 font-semibold text-[#F5F7FA]">{log.action}</td>
                  <td className="py-3 px-4 text-[#A7B0BC]">
                    {log.actor_email} [{log.actor_role}]
                  </td>
                  <td className="py-3 px-4 text-[#737E8C]">
                    {log.resource_type}:{log.resource_id}
                  </td>
                  <td className="py-3 px-4 text-[#A7B0BC]">
                    {JSON.stringify(log.metadata_json)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};
