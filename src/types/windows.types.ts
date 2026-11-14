import { CheckOutcomeStatus, SeverityLevel } from './assessment.types';

export type WindowsPrivilegeLevel = 'STANDARD_USER' | 'ELEVATED_ADMIN';
export type WindowsAgentStatus = 'ACTIVE' | 'OFFLINE' | 'REVOKED';

export interface WindowsAgentRecord {
  id: string;
  organization_id: string;
  hostname: string;
  display_name: string;
  os_edition: string;
  os_version: string;
  os_build: string;
  architecture: '64-bit' | 'ARM64';
  agent_version: string;
  privilege_level: WindowsPrivilegeLevel;
  status: WindowsAgentStatus;
  last_heartbeat_at: string;
  last_ip_address: string;
  enrolled_by_email: string;
  created_at: string;
  revoked_at: string | null;
}

export interface WindowsSystemInventory {
  hostname: string;
  os_caption: string;
  os_version: string;
  os_build: string;
  architecture: string;
  domain_or_workgroup: string;
  uptime_hours: number;
  privilege_level: WindowsPrivilegeLevel;
  cpu_model: string;
  physical_cores: number;
  logical_cores: number;
  cpu_utilization_percent: number;
  ram_total_gb: number;
  ram_used_gb: number;
  ram_available_gb: number;
  disks: Array<{
    mountpoint: string;
    filesystem: 'NTFS' | 'ReFS' | 'FAT32';
    total_gb: number;
    free_gb: number;
    bitlocker_status:
      | 'FullyEncrypted'
      | 'Decrypted'
      | 'EncryptionInProgress'
      | 'Unsupported on Windows Home Edition'
      | 'Requires Elevated Administrator Privileges';
  }>;
  hotfixes: Array<{
    hotfix_id: string;
    description: string;
    installed_on: string;
  }>;
  days_since_last_update: number;
}

export interface WindowsPostureCheck {
  id: string;
  category:
    | 'Microsoft Defender'
    | 'Windows Firewall'
    | 'Windows Update'
    | 'BitLocker Encryption'
    | 'User Account Control (UAC)'
    | 'Remote Desktop (RDP)'
    | 'OpenSSH Server'
    | 'Baseline Hardening'
    | 'Security Event Log';
  title: string;
  status: CheckOutcomeStatus;
  severity: SeverityLevel;
  privilege_required: WindowsPrivilegeLevel;
  evidence_source: string;
  raw_telemetry: string;
  remediation_powershell: string;
  explanation: string;
}

export interface WindowsListeningSocket {
  protocol: 'TCP' | 'UDP';
  local_address: string;
  local_port: number;
  pid: number;
  process_name: string;
  exposure_scope: 'Loopback Only (127.0.0.1)' | 'All Interfaces (0.0.0.0 / ::)';
  risk_level: SeverityLevel;
  notes: string;
}

export interface WifiNetworkAuditEntry {
  ssid: string;
  bssid: string;
  signal_percent: number;
  estimated_dbm: number;
  radio_type: '802.11ax (Wi-Fi 6)' | '802.11ac (Wi-Fi 5)' | '802.11n (Wi-Fi 4)';
  band: '2.4 GHz' | '5 GHz' | '6 GHz';
  channel: number;
  authentication:
    | 'WPA3-Personal'
    | 'WPA3-Enterprise'
    | 'WPA2-Personal'
    | 'WPA2-Enterprise'
    | 'WPA-Personal'
    | 'WEP'
    | 'Open';
  cipher: 'CCMP (AES)' | 'GCMP-256' | 'TKIP' | 'None';
  wps_status: 'Disabled' | 'Enabled (Risk)' | 'Not Advertised';
  is_connected: boolean;
  risk_level: SeverityLevel;
  security_notes: string;
}
