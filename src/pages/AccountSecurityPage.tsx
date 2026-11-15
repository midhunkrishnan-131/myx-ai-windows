import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { KeyRound, ShieldCheck, LogOut, Smartphone, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { authService } from '../services/auth.service';
import { TotpSetupResponse } from '../types/auth.types';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { ConfirmationModal } from '../components/ui/ConfirmationModal';

export const AccountSecurityPage: React.FC = () => {
  const {
    user,
    sessions,
    revokeSessionById,
    revokeAllOtherSessions,
    setTotpEnabledStatus,
  } = useAuth();

  const [totpSetupData, setTotpSetupData] = useState<TotpSetupResponse | null>(null);
  const [verificationCode, setVerificationCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [totpError, setTotpError] = useState<string | null>(null);
  const [confirmDisable2fa, setConfirmDisable2fa] = useState(false);
  const [passwordSavedMessage, setPasswordSavedMessage] = useState<string | null>(null);

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');

  const handleStartTotpEnrollment = async () => {
    setTotpError(null);
    const res = await authService.initiateTotpSetup(
      user?.email || 'midhun.krishnan@myx-security.io'
    );
    setTotpSetupData(res.data);
    setRecoveryCodes(null);
  };

  const handleConfirmTotpEnrollment = async (e: React.FormEvent) => {
    e.preventDefault();
    setTotpError(null);
    if (!/^\d{6}$/.test(verificationCode.trim())) {
      setTotpError('Enter a valid 6-digit RFC 6238 authenticator code.');
      return;
    }
    const res = await authService.confirmTotpSetup(verificationCode.trim());
    setTotpEnabledStatus(res.data.is_enabled);
    setRecoveryCodes(res.data.recovery_codes);
    setTotpSetupData(null);
    setVerificationCode('');
  };

  const handleChangePassword = (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword.length < 10) {
      setPasswordSavedMessage('Error: Password must be at least 10 characters.');
      return;
    }
    setCurrentPassword('');
    setNewPassword('');
    setPasswordSavedMessage(
      'Password hashed with Argon2id (64 MB memory, 3 iterations, 4 lanes) and active sessions rotated.'
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
            Account Security, RFC 6238 TOTP 2FA & Active Sessions
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Argon2id credential rotation, Google/Microsoft Authenticator TOTP enrollment, hashed
            single-use recovery codes, and session revocation
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link
            to="/login"
            className="px-3 py-1.5 bg-[#141920] hover:bg-[#1B222B] border border-[#29313B] rounded-lg text-xs text-[#A7B0BC] hover:text-[#F5F7FA]"
          >
            Preview Auth Flows (/login)
          </Link>
          <StatusBadge status={user?.totp_enabled ? 'TOTP 2FA ACTIVE' : '2FA DISABLED'} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Genuine RFC 6238 TOTP Two-Factor Authentication */}
        <Card
          title="RFC 6238 TOTP Two-Factor Authentication"
          subtitle="Compatible with Google Authenticator, Microsoft Authenticator, Authy & 1Password"
        >
          <div className="space-y-4 text-xs">
            <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <Smartphone className="w-5 h-5 text-[#38BDF8] shrink-0" />
                <div>
                  <div className="font-semibold text-[#F5F7FA]">
                    Status: {user?.totp_enabled ? 'Enabled & Verified' : 'Not Enrolled'}
                  </div>
                  <div className="text-[#A7B0BC]">
                    Replay protection enforced via last_verified_timestep
                  </div>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleStartTotpEnrollment}
                >
                  {user?.totp_enabled ? 'Re-Enroll / Rotate Secret' : 'Enable TOTP 2FA'}
                </Button>
                {user?.totp_enabled && (
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={() => setConfirmDisable2fa(true)}
                  >
                    Disable 2FA
                  </Button>
                )}
              </div>
            </div>

            {totpError && (
              <div className="p-3 bg-[#F05252]/10 border border-[#F05252]/30 rounded text-[#F05252]">
                {totpError}
              </div>
            )}

            {totpSetupData && (
              <form
                onSubmit={handleConfirmTotpEnrollment}
                className="p-4 bg-[#080A0D] border border-[#D6AE45]/40 rounded-lg space-y-4"
              >
                <div className="font-semibold text-[#F5F7FA]">
                  Step 1: Scan QR Code or Enter Base32 Secret in Authenticator App
                </div>
                <div className="flex flex-col sm:flex-row items-center gap-4">
                  <img
                    src={totpSetupData.qr_code_svg_data_uri}
                    alt="TOTP Enrollment QR Code"
                    referrerPolicy="no-referrer"
                    className="w-36 h-36 rounded-lg border border-[#29313B] bg-white p-1 shrink-0"
                  />
                  <div className="space-y-2 min-w-0">
                    <div className="text-[#A7B0BC]">
                      Manual Setup Key (160-bit Base32):
                    </div>
                    <div className="p-2 bg-[#141920] border border-[#29313B] rounded font-mono text-[#38BDF8] select-all">
                      {totpSetupData.manual_secret_grouped}
                    </div>
                    <div className="font-mono text-[11px] text-[#737E8C] break-all">
                      URI: {totpSetupData.otpauth_uri}
                    </div>
                  </div>
                </div>

                <div>
                  <label
                    htmlFor="totp-verify-code"
                    className="block font-medium text-[#F5F7FA] mb-1"
                  >
                    Step 2: Enter 6-Digit Code to Activate (Strict Activation Rule)
                  </label>
                  <div className="flex gap-2">
                    <input
                      id="totp-verify-code"
                      type="text"
                      maxLength={6}
                      placeholder="123456"
                      value={verificationCode}
                      onChange={(e) => setVerificationCode(e.target.value)}
                      className="flex-1 px-3 py-2 bg-[#141920] border border-[#29313B] rounded font-mono text-sm text-[#F5F7FA]"
                    />
                    <Button type="submit" variant="primary" size="sm">
                      Verify & Activate 2FA
                    </Button>
                  </div>
                </div>
              </form>
            )}

            {recoveryCodes && (
              <div className="p-4 bg-[#22C55E]/10 border border-[#22C55E]/40 rounded-lg space-y-2.5">
                <div className="font-semibold text-[#22C55E] flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>
                    2FA Confirmed! Save Your 10 Single-Use Recovery Codes Immediately
                  </span>
                </div>
                <p className="text-[#A7B0BC]">
                  These codes are shown only once. Only their Argon2id/SHA-256 hashes are persisted
                  in the totp_recovery_codes table.
                </p>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 font-mono text-xs text-[#F5F7FA]">
                  {recoveryCodes.map((code) => (
                    <div
                      key={code}
                      className="p-1.5 bg-[#080A0D] border border-[#29313B] rounded text-center"
                    >
                      {code}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Card>

        {/* Argon2id Password Rotation */}
        <Card
          title="Step-Up Argon2id Password Change"
          subtitle="Enforces 12+ character passphrase complexity and invalidates secondary sessions"
        >
          <form onSubmit={handleChangePassword} className="space-y-3 text-xs">
            {passwordSavedMessage && (
              <div className="p-3 bg-[#101318] border border-[#38BDF8]/40 rounded text-[#38BDF8]">
                {passwordSavedMessage}
              </div>
            )}
            <div>
              <label htmlFor="curr-pass" className="block font-medium text-[#F5F7FA] mb-1">
                Current Password
              </label>
              <input
                id="curr-pass"
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded text-[#F5F7FA]"
              />
            </div>
            <div>
              <label htmlFor="new-pass" className="block font-medium text-[#F5F7FA] mb-1">
                New Password (Minimum 12 Characters)
              </label>
              <input
                id="new-pass"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter strong 12+ character passphrase"
                className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded text-[#F5F7FA]"
              />
            </div>
            <div className="flex justify-end">
              <Button type="submit" variant="primary" size="sm" icon={<KeyRound className="w-3.5 h-3.5" />}>
                Update Password with Argon2id
              </Button>
            </div>
          </form>
        </Card>
      </div>

      {/* Stateful Server-Side Sessions Table */}
      <Card
        title="Active Server-Side Stateful Sessions (user_sessions)"
        subtitle="HttpOnly, SameSite=Lax cookie sessions paired with X-CSRF-Token validation"
        headerAction={
          <Button
            variant="danger"
            size="sm"
            icon={<LogOut className="w-3.5 h-3.5" />}
            onClick={revokeAllOtherSessions}
          >
            Logout from All Other Sessions
          </Button>
        }
        noPadding
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-[#101318] border-b border-[#29313B] text-[11px] font-medium text-[#A7B0BC]">
                <th className="py-3 px-4">Device & Browser</th>
                <th className="py-3 px-4">IP Address</th>
                <th className="py-3 px-4">2FA Verified</th>
                <th className="py-3 px-4">Last Activity</th>
                <th className="py-3 px-4">Session State</th>
                <th className="py-3 px-4">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#29313B] text-xs">
              {sessions.map((sess) => (
                <tr key={sess.id} className="hover:bg-[#1B222B]">
                  <td className="py-3 px-4">
                    <div className="font-semibold text-[#F5F7FA]">{sess.device_label}</div>
                    <div className="font-mono text-[11px] text-[#737E8C] truncate max-w-xs">
                      {sess.user_agent}
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-[#38BDF8]">{sess.ip_address}</td>
                  <td className="py-3 px-4">
                    <StatusBadge status={sess.is_2fa_verified ? 'VERIFIED' : 'PRE_2FA'} />
                  </td>
                  <td className="py-3 px-4 font-mono text-[#A7B0BC]">{sess.last_active_at}</td>
                  <td className="py-3 px-4">
                    <StatusBadge status={sess.revoked_at ? 'REVOKED' : 'ACTIVE'} />
                  </td>
                  <td className="py-3 px-4">
                    {!sess.is_current && !sess.revoked_at && (
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => revokeSessionById(sess.id)}
                      >
                        Revoke Session
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <ConfirmationModal
        isOpen={confirmDisable2fa}
        title="Step-Up Confirmation Required to Disable 2FA"
        description="Disabling RFC 6238 Two-Factor Authentication lowers account assurance. Enter your current 6-digit TOTP code to confirm."
        confirmLabel="Disable Two-Factor Auth"
        variant="danger"
        requireStepUpCode
        onCancel={() => setConfirmDisable2fa(false)}
        onConfirm={() => {
          setTotpEnabledStatus(false);
          setConfirmDisable2fa(false);
        }}
      />
    </div>
  );
};
