import { apiClient } from '../services/apiClient';

export interface ProjectZipExportResponse {
  ok: boolean;
  filename: string;
  sizeBytes: number;
  fileCount: number;
  sha256: string;
  base64: string;
}

/**
 * Downloads the verified MYX AI (Windows Edition) project ZIP archive
 * using a JSON Base64 -> Uint8Array -> Blob pipeline so that proxy/iframe
 * layers never corrupt binary streams or substitute HTML fallback pages.
 */
export async function downloadAntigravityProjectZip(
  onStatus?: (message: string) => void
): Promise<{ ok: boolean; message: string }> {
  try {
    onStatus?.('Packaging & verifying MYX AI Antigravity ZIP archive...');

    const res = await fetch('/api/v1/export/project-zip', {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'X-CSRF-Token': apiClient.getCsrfToken(),
      },
      credentials: 'include',
    });

    if (!res.ok) {
      throw new Error(`Backend returned HTTP ${res.status}`);
    }

    const payload = (await res.json()) as ProjectZipExportResponse;
    if (!payload.base64) {
      throw new Error('Missing base64 ZIP payload from server');
    }

    const binaryString = window.atob(payload.base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    // Verify official ZIP magic header: PK\x03\x04 (0x50, 0x4B, 0x03, 0x04)
    if (
      bytes.length < 4 ||
      bytes[0] !== 0x50 ||
      bytes[1] !== 0x4b ||
      bytes[2] !== 0x03 ||
      bytes[3] !== 0x04
    ) {
      throw new Error('Invalid ZIP header signature');
    }

    const blob = new Blob([bytes], { type: 'application/zip' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = payload.filename || 'myx-ai-windows-edition-antigravity.zip';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 5000);

    const sizeKb = (bytes.length / 1024).toFixed(1);
    const msg = `Downloaded verified ${payload.filename} (${payload.fileCount} files, ${sizeKb} KB, SHA-256: ${payload.sha256.slice(0, 12)}…). Ready to extract on Windows 10/11 & import into Google Antigravity.`;
    onStatus?.(msg);
    return { ok: true, message: msg };
  } catch (err) {
    const errMsg =
      err instanceof Error ? err.message : 'Unable to download ZIP archive';
    onStatus?.(`Download error: ${errMsg}`);
    return { ok: false, message: errMsg };
  }
}
