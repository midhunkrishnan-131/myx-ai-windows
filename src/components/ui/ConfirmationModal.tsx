import React from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { Button } from './Button';

export interface ConfirmationModalProps {
  isOpen: boolean;
  title: string;
  description: string;
  confirmLabel?: string;
  variant?: 'danger' | 'primary';
  requireStepUpCode?: boolean;
  onConfirm: (stepUpCode?: string) => void;
  onCancel: () => void;
}

export const ConfirmationModal: React.FC<ConfirmationModalProps> = ({
  isOpen,
  title,
  description,
  confirmLabel = 'Confirm Action',
  variant = 'danger',
  requireStepUpCode = false,
  onConfirm,
  onCancel,
}) => {
  const [stepUpInput, setStepUpInput] = React.useState('');

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-modal-title"
    >
      <div className="w-full max-w-md bg-[#141920] border border-[#29313B] rounded-lg overflow-hidden shadow-xl">
        <div className="px-5 py-4 bg-[#101318] border-b border-[#29313B] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <AlertTriangle
              className={`w-5 h-5 ${
                variant === 'danger' ? 'text-[#F05252]' : 'text-[#F59E0B]'
              }`}
              aria-hidden="true"
            />
            <h3 id="confirm-modal-title" className="text-sm font-semibold text-[#F5F7FA]">
              {title}
            </h3>
          </div>
          <button
            type="button"
            onClick={onCancel}
            aria-label="Close confirmation dialog"
            className="text-[#A7B0BC] hover:text-[#F5F7FA] p-1 rounded"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          <p className="text-xs sm:text-sm text-[#A7B0BC] leading-relaxed">{description}</p>
          {requireStepUpCode && (
            <div>
              <label
                htmlFor="step-up-totp"
                className="block text-xs font-medium text-[#F5F7FA] mb-1.5"
              >
                Step-Up Verification: Enter 6-Digit Authenticator TOTP Code
              </label>
              <input
                id="step-up-totp"
                type="text"
                maxLength={6}
                placeholder="123456"
                value={stepUpInput}
                onChange={(e) => setStepUpInput(e.target.value)}
                className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-sm font-mono text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
              />
            </div>
          )}
        </div>
        <div className="px-5 py-3 bg-[#101318] border-t border-[#29313B] flex items-center justify-end gap-2.5">
          <Button variant="secondary" size="sm" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            variant={variant}
            size="sm"
            disabled={requireStepUpCode && stepUpInput.trim().length < 6}
            onClick={() => {
              onConfirm(stepUpInput);
              setStepUpInput('');
            }}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
};
