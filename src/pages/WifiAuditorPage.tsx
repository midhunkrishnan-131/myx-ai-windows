import React from 'react';
import { Wifi, Info, ShieldAlert } from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { Card } from '../components/ui/Card';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { StatusBadge } from '../components/ui/StatusBadge';
import { CodeEvidenceBlock } from '../components/ui/CodeEvidenceBlock';

export const WifiAuditorPage: React.FC = () => {
  const { wifiNetworks } = useSystemStatus();

  const connectedWifi = wifiNetworks.find((w) => w.is_connected);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
            Wi-Fi Security Auditor (Windows 10/11)
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Defensive wireless environment posture via local Windows Agent read-only{' '}
            <code className="font-mono text-[#38BDF8]">netsh wlan</code> telemetry
          </p>
        </div>
        <StatusBadge status="DEFENSIVE READ-ONLY" />
      </div>

      {/* Windows 10 24H2 & Windows 11 Location Permission Notice */}
      <div className="p-4 bg-[#141920] border border-[#29313B] rounded-lg flex items-start gap-3">
        <Info className="w-5 h-5 text-[#38BDF8] shrink-0 mt-0.5" aria-hidden="true" />
        <div className="text-xs text-[#A7B0BC] space-y-1 leading-relaxed">
          <div className="font-semibold text-[#F5F7FA]">
            Windows 10 (24H2) & Windows 11 WLAN Location Permission Requirement
          </div>
          <p>
            On Microsoft Windows 11 and recent Windows 10 builds, OS privacy controls require{' '}
            <strong className="text-[#F5F7FA]">
              Settings → Privacy & security → Location → Let desktop apps access your location
            </strong>{' '}
            to be enabled before <code className="font-mono">netsh wlan show networks mode=bssid</code>{' '}
            or <code className="font-mono">WlanGetNetworkBssList</code> will return visible BSSIDs.
            MYX AI strictly performs passive beacon inspection and never performs packet injection,
            deauthentication frames, or WPA handshake capture.
          </p>
        </div>
      </div>

      {connectedWifi && (
        <Card
          title={`Connected Wireless Interface — ${connectedWifi.ssid}`}
          subtitle="Active Windows WLAN adapter telemetry from WIN11-SECOPS-01"
        >
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg">
              <div className="text-[#A7B0BC]">Connected SSID / BSSID</div>
              <div className="font-mono font-semibold text-[#F5F7FA] mt-1">
                {connectedWifi.ssid}
              </div>
              <div className="font-mono text-[11px] text-[#737E8C]">{connectedWifi.bssid}</div>
            </div>
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg">
              <div className="text-[#A7B0BC]">Authentication & Cipher</div>
              <div className="font-mono font-semibold text-[#22C55E] mt-1">
                {connectedWifi.authentication}
              </div>
              <div className="font-mono text-[11px] text-[#737E8C]">{connectedWifi.cipher}</div>
            </div>
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg">
              <div className="text-[#A7B0BC]">Radio / Band / Channel</div>
              <div className="font-mono font-semibold text-[#F5F7FA] mt-1">
                {connectedWifi.band} (Ch {connectedWifi.channel})
              </div>
              <div className="font-mono text-[11px] text-[#737E8C]">{connectedWifi.radio_type}</div>
            </div>
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg">
              <div className="text-[#A7B0BC]">Signal Quality & WPS</div>
              <div className="font-mono font-semibold text-[#F5F7FA] mt-1 tabular-nums">
                {connectedWifi.signal_percent}% ({connectedWifi.estimated_dbm} dBm)
              </div>
              <div className="font-mono text-[11px] text-[#737E8C]">
                WPS: {connectedWifi.wps_status}
              </div>
            </div>
          </div>
        </Card>
      )}

      <Card
        title="Visible BSSID Beacon & Encryption Posture Ledger"
        subtitle="Flags Open networks, deprecated WEP/WPA1/TKIP ciphers, WPS exposure, and duplicate SSID evil-twin indicators"
        noPadding
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-[#101318] border-b border-[#29313B] text-[11px] font-medium text-[#A7B0BC]">
                <th className="py-3 px-4">SSID</th>
                <th className="py-3 px-4">BSSID (MAC)</th>
                <th className="py-3 px-4">Band / Ch</th>
                <th className="py-3 px-4">Signal</th>
                <th className="py-3 px-4">Authentication / Cipher</th>
                <th className="py-3 px-4">WPS Status</th>
                <th className="py-3 px-4">Risk</th>
                <th className="py-3 px-4">Defensive Hardening Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#29313B] text-xs">
              {wifiNetworks.map((net, idx) => (
                <tr key={`${net.bssid}-${idx}`} className="hover:bg-[#1B222B]">
                  <td className="py-3 px-4 font-medium text-[#F5F7FA]">
                    {net.ssid}{' '}
                    {net.is_connected && (
                      <span className="ml-1.5 text-[10px] font-mono text-[#22C55E]">
                        [CONNECTED]
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 font-mono text-[#38BDF8]">{net.bssid}</td>
                  <td className="py-3 px-4 font-mono text-[#A7B0BC] whitespace-nowrap">
                    {net.band} · Ch {net.channel}
                  </td>
                  <td className="py-3 px-4 font-mono text-[#F5F7FA] tabular-nums">
                    {net.signal_percent}% ({net.estimated_dbm} dBm)
                  </td>
                  <td className="py-3 px-4 font-mono">
                    <div className="text-[#F5F7FA]">{net.authentication}</div>
                    <div className="text-[11px] text-[#737E8C]">{net.cipher}</div>
                  </td>
                  <td className="py-3 px-4 font-mono text-[#A7B0BC]">{net.wps_status}</td>
                  <td className="py-3 px-4">
                    <SeverityBadge severity={net.risk_level} />
                  </td>
                  <td className="py-3 px-4 text-[#A7B0BC]">{net.security_notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <CodeEvidenceBlock
        title="Windows Local Agent Read-Only WLAN Collector (windows_agent/collectors/wifi_auditor.py)"
        language="powershell"
        code={`# Strictly read-only Windows WLAN diagnostic commands executed by MYX-Windows-Agent:
netsh wlan show interfaces
netsh wlan show networks mode=bssid`}
      />
    </div>
  );
};
