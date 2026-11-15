import React, { createContext, useContext, useState } from 'react';
import { UserProfile, UserRole, UserSession } from '../types/auth.types';
import { INITIAL_CURRENT_USER, INITIAL_USER_SESSIONS } from '../data/seedPreviewData';

interface AuthContextValue {
  user: UserProfile | null;
  isAuthenticated: boolean;
  sessions: UserSession[];
  switchRoleForDemo: (role: UserRole) => void;
  loginWithCredentials: (email: string, role?: UserRole) => void;
  logoutCurrentSession: () => void;
  revokeSessionById: (sessionId: string) => void;
  revokeAllOtherSessions: () => void;
  setTotpEnabledStatus: (enabled: boolean) => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Session authentication state persisted per-browser tab in sessionStorage
  const [user, setUser] = useState<UserProfile | null>(() => {
    try {
      const saved = window.sessionStorage.getItem('myx_auth_user');
      if (saved) {
        return JSON.parse(saved);
      }
    } catch {
      // Ignore sessionStorage errors
    }
    return null;
  });
  const [sessions, setSessions] = useState<UserSession[]>(INITIAL_USER_SESSIONS);

  const switchRoleForDemo = (role: UserRole) => {
    setUser((prev) => {
      if (!prev) return null;
      const updated = {
        ...prev,
        role,
        job_title:
          role === 'ADMIN'
            ? 'Principal Security Architect'
            : role === 'SECURITY_ANALYST'
            ? 'Senior Windows & Network Security Analyst'
            : 'ISO 27001 / SOC 2 Compliance Reviewer',
      };
      try {
        window.sessionStorage.setItem('myx_auth_user', JSON.stringify(updated));
      } catch {}
      return updated;
    });
  };

  const loginWithCredentials = (email: string, role: UserRole = 'ADMIN') => {
    const newUser: UserProfile = {
      ...INITIAL_CURRENT_USER,
      email,
      role,
      last_login_at: new Date().toISOString(),
    };
    setUser(newUser);
    try {
      window.sessionStorage.setItem('myx_auth_user', JSON.stringify(newUser));
    } catch {}
  };

  const logoutCurrentSession = () => {
    setUser(null);
    try {
      window.sessionStorage.removeItem('myx_auth_user');
    } catch {}
    void fetch('/api/v1/auth/logout', { method: 'POST' }).catch(() => {});
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
        sessions,
        switchRoleForDemo,
        loginWithCredentials,
        logoutCurrentSession,
        revokeSessionById,
        revokeAllOtherSessions,
        setTotpEnabledStatus,
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
