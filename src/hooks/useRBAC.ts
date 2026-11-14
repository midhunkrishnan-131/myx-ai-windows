import { useAuthContext } from '../context/AuthContext';
import { checkRolePermission, RbacCapability } from '../utils/securityLogic';
import { UserRole } from '../types/auth.types';

export function useRBAC() {
  const { user } = useAuthContext();
  const currentRole: UserRole = user?.role || 'VIEWER';

  const can = (capability: RbacCapability): boolean => {
    return checkRolePermission(currentRole, capability);
  };

  const hasRole = (allowedRoles: UserRole[]): boolean => {
    return allowedRoles.includes(currentRole);
  };

  return {
    role: currentRole,
    can,
    hasRole,
    isAdmin: currentRole === 'ADMIN',
    isAnalyst: currentRole === 'SECURITY_ANALYST',
    isViewer: currentRole === 'VIEWER',
  };
}
