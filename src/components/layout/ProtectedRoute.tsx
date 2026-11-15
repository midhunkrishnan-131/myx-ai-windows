import React from 'react';
import { Link, Navigate, useLocation } from 'react-router-dom';
import { ShieldAlert } from 'lucide-react';
import { UserRole } from '../../types/auth.types';
import { useAuth } from '../../hooks/useAuth';
import { Card } from '../ui/Card';
import { Button } from '../ui/Button';

export const ProtectedRoute: React.FC<{
  allowedRoles: UserRole[];
  children: React.ReactNode;
}> = ({ allowedRoles, children }) => {
  const { user, switchRoleForDemo } = useAuth();
  const location = useLocation();

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  const currentRole: UserRole = user.role;

  if (!allowedRoles.includes(currentRole)) {
    return (
      <div className="max-w-2xl mx-auto my-8">
        <Card
          title="RBAC Authorization Boundary — Access Restricted (HTTP 403)"
          subtitle="Role-Based Access Control enforced by frontend route guard and FastAPI require_roles() dependency"
        >
          <div className="space-y-4">
            <div className="flex items-start gap-3 p-4 bg-[#F05252]/10 border border-[#F05252]/30 rounded-lg">
              <ShieldAlert className="w-5 h-5 text-[#F05252] shrink-0 mt-0.5" />
              <div className="text-xs sm:text-sm text-[#A7B0BC] space-y-1">
                <p className="text-[#F5F7FA] font-medium">
                  Your current session role (<span className="font-mono">{currentRole}</span>) is
                  not permitted to access this module.
                </p>
                <p>
                  Required Role(s):{' '}
                  <span className="font-mono text-[#F5F7FA]">{allowedRoles.join(' or ')}</span>
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Button
                variant="primary"
                size="sm"
                onClick={() => switchRoleForDemo(allowedRoles[0])}
              >
                Switch Session Role to {allowedRoles[0]}
              </Button>
              <Link
                to="/dashboard"
                className="px-3 py-1.5 text-xs font-medium text-[#A7B0BC] hover:text-[#F5F7FA] border border-[#29313B] rounded-lg"
              >
                Return to Dashboard
              </Link>
            </div>
          </div>
        </Card>
      </div>
    );
  }

  return <>{children}</>;
};
