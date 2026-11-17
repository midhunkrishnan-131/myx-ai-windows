import React, { createContext, useContext, useState, useEffect } from 'react';
import { UserProfile, UserRole, UserSession } from '../types/auth.types';

interface AuthContextValue {
  user: UserProfile | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  sessions: UserSession[];
  switchRoleForDemo: (role: UserRole) => void;
  loginWithCredentials: (emailOrUser: string | UserProfile, role?: UserRole) => void;
  logoutCurrentSession: () => void;
  revokeSessionById: (sessionId: string) => void;
  revokeAllOtherSessions: () => void;
  setTotpEnabledStatus: (enabled: boolean) => void;
  refreshSession: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [sessions, setSessions] = useState<UserSession[]>([]);

  // Authenticate against server-side session identity on application mount (C-03)
  const verifyCurrentSession = async () => {
    try {
      const res = await fetch('/api/v1/auth/me', {
        method: 'GET',
        credentials: 'include',
        headers: { Accept: 'application/json' },
      });
      if (res.ok) {
        const userData = (await res.json()) as UserProfile;
        setUser(userData);
      } else {
        setUser(null);
      }
    } catch {
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    verifyCurrentSession();
  }, []);

  // Demo role-switch disabled in hardened production mode (H-01)
  const switchRoleForDemo = (role: UserRole) => {
    console.warn(
      `[MYX AI Security] Client-side role switching is prohibited. Role (${role}) must be derived from server-side session.`
    );
  };

  const loginWithCredentials = (emailOrUser: string | UserProfile, role?: UserRole) => {
    if (typeof emailOrUser === 'object' && emailOrUser !== null) {
      setUser(emailOrUser);
      return;
    }
    // Re-verify session identity from server
    void verifyCurrentSession();
  };

  const logoutCurrentSession = () => {
    setUser(null);
    void fetch('/api/v1/auth/logout', {
      method: 'POST',
      credentials: 'include',
    }).catch(() => {});
  };

  const revokeSessionById = (sessionId: string) => {
    setSessions((prev) =>
      prev.map((s) =>
        s.id === sessionId ? { ...s, revoked_at: new Date().toISOString() } : s
      )
    );
  };

  const revokeAllOtherSessions = () => {
    const now = new Date().toISOString();
    setSessions((prev) =>
      prev.map((s) => (s.is_current ? s : { ...s, revoked_at: now }))
    );
  };

  const setTotpEnabledStatus = (enabled: boolean) => {
    setUser((prev) => (prev ? { ...prev, totp_enabled: enabled } : null));
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: Boolean(user),
        isLoading,
        sessions,
        switchRoleForDemo,
        loginWithCredentials,
        logoutCurrentSession,
        revokeSessionById,
        revokeAllOtherSessions,
        setTotpEnabledStatus,
        refreshSession: verifyCurrentSession,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuthContext(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuthContext must be used inside an AuthProvider');
  }
  return ctx;
}
