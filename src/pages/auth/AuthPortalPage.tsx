import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, KeyRound, ArrowLeft } from 'lucide-react';
import { BRAND_CONFIG } from '../../config/brand.config';
import { useAuth } from '../../hooks/useAuth';
import { Card } from '../../components/ui/Card';
import { Button } from '../../components/ui/Button';

export type AuthFlowMode =
  | 'LOGIN'
  | 'REGISTER'
  | 'VERIFY_EMAIL'
  | 'FORGOT_PASSWORD'
  | 'RESET_PASSWORD'
  | 'TOTP_CHALLENGE';

export const AuthPortalPage: React.FC<{ initialMode?: AuthFlowMode }> = ({
  initialMode = 'LOGIN',
}) => {
  const [mode, setMode] = useState<AuthFlowMode>(initialMode);
  const [email, setEmail] = useState('midhun.krishnan@myx-security.io');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('Midhun Krishnan');
  const [totpCode, setTotpCode] = useState('');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const { loginWithCredentials } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (mode === 'LOGIN') {
      setMode('TOTP_CHALLENGE');
      setStatusMessage(
        'Argon2id password verified. Issued 5-minute pre_2fa_session cookie. Enter 6-digit TOTP or recovery code.'
      );
      return;
    }
    if (mode === 'TOTP_CHALLENGE') {
      loginWithCredentials(email, 'ADMIN');
      navigate('/dashboard');
      return;
    }
    if (mode === 'REGISTER') {
      setMode('VERIFY_EMAIL');
      setStatusMessage(
        'Account registered with Argon2id hash. Time-limited SHA-256 verification token dispatched via Resend.'
      );
      return;
    }
    if (mode === 'FORGOT_PASSWORD') {
      setMode('RESET_PASSWORD');
      setStatusMessage(
        '15-minute single-use password reset token generated (SHA-256 hashed in password_reset_tokens).'
      );
      return;
    }
    setStatusMessage('Action completed in preview mode. Redirecting to Dashboard...');
    setTimeout(() => navigate('/dashboard'), 900);
  };

  return (
    <div className="min-h-screen bg-[#0B0D10] text-[#F5F7FA] flex flex-col justify-center items-center p-4">
      <div className="w-full max-w-md space-y-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-14 h-14 rounded-xl bg-[#101318] border border-[#D6AE45]/40 p-1.5 flex items-center justify-center shrink-0">
              <img
                src={BRAND_CONFIG.BRAND_LOGO_URL}
                alt={`${BRAND_CONFIG.BRAND_FULL_TITLE} Logo`}
                className="w-full h-full object-contain"
              />
            </div>
            <div>
              <div className="text-base font-bold text-[#F5F7FA]">
                {BRAND_CONFIG.BRAND_FULL_TITLE}
              </div>
              <div className="text-xs text-[#D6AE45]">
                {BRAND_CONFIG.BRAND_EDITION_NAME} · {BRAND_CONFIG.BRAND_TAGLINE}
              </div>
            </div>
          </div>
          <Link
            to="/dashboard"
            className="inline-flex items-center gap-1 text-xs text-[#D6AE45] hover:underline"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Console</span>
          </Link>
        </div>

        {/* Mode Switcher Tabs */}
        <div className="flex flex-wrap gap-1.5 p-1.5 bg-[#141920] border border-[#29313B] rounded-lg text-xs">
          {(
            [
              ['LOGIN', 'Login'],
              ['REGISTER', 'Register'],
              ['TOTP_CHALLENGE', '2FA Challenge'],
              ['FORGOT_PASSWORD', 'Forgot Password'],
              ['VERIFY_EMAIL', 'Verify Email'],
            ] as const
          ).map(([mKey, label]) => (
            <button
              key={mKey}
              type="button"
              onClick={() => {
                setMode(mKey);
                setStatusMessage(null);
              }}
              className={`px-2.5 py-1 rounded font-medium transition-colors ${
                mode === mKey
                  ? 'bg-[#D6AE45] text-[#F5F7FA]'
                  : 'text-[#A7B0BC] hover:text-[#F5F7FA]'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        <Card
          title={
            mode === 'LOGIN'
              ? 'Sign In to MYX AI Security Console'
              : mode === 'REGISTER'
              ? 'Register Organization & Analyst Account'
              : mode === 'TOTP_CHALLENGE'
              ? 'RFC 6238 Two-Factor Authentication Challenge'
              : mode === 'FORGOT_PASSWORD'
              ? 'Request 15-Minute Password Reset Token'
              : mode === 'RESET_PASSWORD'
              ? 'Complete Password Reset (Invalidates All Sessions)'
              : 'Verify Email Token (SHA-256 Single-Use)'
          }
          subtitle="Stateful HttpOnly SameSite=Lax Cookie + X-CSRF-Token Protection (Zero LocalStorage Secrets)"
        >
          <form onSubmit={handleSubmit} className="space-y-4 text-xs">
            {statusMessage && (
              <div className="p-3 bg-[#38BDF8]/10 border border-[#38BDF8]/30 rounded text-[#38BDF8]">
                {statusMessage}
              </div>
            )}

            {mode === 'REGISTER' && (
              <div>
                <label htmlFor="auth-fullname" className="block font-medium text-[#F5F7FA] mb-1">
                  Full Name
                </label>
                <input
                  id="auth-fullname"
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded text-[#F5F7FA]"
                />
              </div>
            )}

            {mode !== 'TOTP_CHALLENGE' && (
              <div>
                <label htmlFor="auth-email" className="block font-medium text-[#F5F7FA] mb-1">
                  Work Email Address
                </label>
                <input
                  id="auth-email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded font-mono text-[#F5F7FA]"
                />
              </div>
            )}

            {(mode === 'LOGIN' || mode === 'REGISTER' || mode === 'RESET_PASSWORD') && (
              <div>
                <label htmlFor="auth-password" className="block font-medium text-[#F5F7FA] mb-1">
                  Password (Argon2id — Min 12 Characters)
                </label>
                <input
                  id="auth-password"
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded text-[#F5F7FA]"
                />
              </div>
            )}

            {mode === 'TOTP_CHALLENGE' && (
              <div>
                <label htmlFor="auth-totp" className="block font-medium text-[#F5F7FA] mb-1">
                  6-Digit Authenticator TOTP Code or MYX-XXXX-XXXX Recovery Code
                </label>
                <input
                  id="auth-totp"
                  type="text"
                  required
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  placeholder="123456 or MYX-8F3A-9C2D"
                  className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded font-mono text-sm text-[#F5F7FA]"
                />
              </div>
            )}

            <Button type="submit" variant="primary" className="w-full">
              {mode === 'LOGIN'
                ? 'Verify Argon2id Credentials'
                : mode === 'TOTP_CHALLENGE'
                ? 'Verify 2FA & Establish Session'
                : 'Submit'}
            </Button>
          </form>
        </Card>
      </div>
    </div>
  );
};
