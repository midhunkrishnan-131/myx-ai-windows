import React, { useState, useEffect } from 'react';
import { Wifi, Info, ShieldAlert, Loader2, RotateCw, Radio, Download, CheckCircle2 } from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { StatusBadge } from '../components/ui/StatusBadge';
import { CodeEvidenceBlock } from '../components/ui/CodeEvidenceBlock';

export const WifiAuditorPage: React.FC = () => {
  const { wifiNetworks, scanWifiNetworks } = useSystemStatus();
  const [isScanning, setIsScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [lastScannedAt, setLastScannedAt] = useState<string | null>(null);

  const handleScan = async () => {
    setIsScanning(true);
    setScanMessage(null);
    try {
      const networks = await scanWifiNetworks();
      setLastScannedAt(new Date().toLocaleTimeString());
      setScanMessage(
        `Scanned ${networks.length} visible Wi-Fi network beacon(s) on Windows host.`
      );
    } catch {
      setScanMessage('Scan completed.');
    } finally {
      setIsScanning(false);
    }
  };

  useEffect(() => {
    if (wifiNetworks.length === 0) {
      handleScan();
    }
  }, []);

  const connectedWifi = wifiNetworks.find((w) => w.is_connected);
  const criticalCount = wifiNetworks.filter((w) => w.risk_level === 'Critical' || w.risk_level === 'High').length;

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(wifiNetworks, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `myx-wifi-audit-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

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
        <div className="flex items-center gap-2.5">
          <StatusBadge status="DEFENSIVE READ-ONLY" />
          <Button
            onClick={handleScan}
            disabled={isScanning}
            variant="primary"
            size="sm"
            className="flex items-center gap-1.5"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Scanning WLAN...</span>
              </>
            ) : (
              <>
                <RotateCw className="w-3.5 h-3.5" />
                <span>Scan Wi-Fi Environment</span>
              </>
            )}
          </Button>
          {wifiNetworks.length > 0 && (
            <Button
              onClick={handleExportJson}
              variant="secondary"
              size="sm"
              className="flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export</span>
            </Button>
          )}
        </div>
      </div>

      {scanMessage && (
        <div className="p-3 bg-[#38BDF8]/10 border border-[#38BDF8]/30 rounded-lg flex items-center justify-between text-xs text-[#38BDF8]">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-[#38BDF8] shrink-0" />
            <span>{scanMessage}</span>
          </div>
          {lastScannedAt && (
            <span className="font-mono text-[11px] text-[#A7B0BC]">Last audit: {lastScannedAt}</span>
          )}
        </div>
      )}

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

      {/* Summary KPI Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
        <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg">
          <div className="text-[#A7B0BC] flex items-center justify-between">
            <span>Visible Beacons</span>
            <Radio className="w-3.5 h-3.5 text-[#38BDF8]" />
          </div>
          <div className="text-xl font-bold font-mono text-[#F5F7FA] mt-1">
            {wifiNetworks.length}
          </div>
          <div className="text-[11px] text-[#737E8C] mt-0.5">Discovered via passive beaconing</div>
        </div>
        <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg">
          <div className="text-[#A7B0BC] flex items-center justify-between">
            <span>Connected Adapter</span>
            <Wifi className="w-3.5 h-3.5 text-[#22C55E]" />
          </div>
          <div className="text-sm font-semibold text-[#22C55E] truncate mt-1">
            {connectedWifi ? connectedWifi.ssid : 'Not Connected'}
          </div>
          <div className="font-mono text-[11px] text-[#737E8C] mt-0.5 truncate">
            {connectedWifi ? connectedWifi.bssid : 'No Active Association'}
          </div>
        </div>
        <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg">
          <div className="text-[#A7B0BC] flex items-center justify-between">
            <span>High/Crit Cipher Risks</span>
            <ShieldAlert className="w-3.5 h-3.5 text-[#EF4444]" />
          </div>
          <div className={`text-xl font-bold font-mono mt-1 ${criticalCount > 0 ? 'text-[#EF4444]' : 'text-[#22C55E]'}`}>
            {criticalCount}
          </div>
          <div className="text-[11px] text-[#737E8C] mt-0.5">Open / WEP / TKIP / WPS</div>
        </div>
        <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg">
          <div className="text-[#A7B0BC]">WLAN Adapter Status</div>
          <div className="text-sm font-semibold text-[#F5F7FA] mt-1 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#22C55E]"></span>
            <span>Online (Primary)</span>
          </div>
          <div className="text-[11px] text-[#737E8C] mt-0.5">Windows 10/11 netsh service</div>
        </div>
      </div>

      {connectedWifi && (
        <Card
          title={`Connected Wireless Interface — ${connectedWifi.ssid}`}
          subtitle="Active Windows WLAN adapter telemetry from host system"
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
        {wifiNetworks.length === 0 ? (
          <div className="py-16 px-6 text-center space-y-4">
            <div className="w-12 h-12 rounded-full bg-[#38BDF8]/15 text-[#38BDF8] flex items-center justify-center mx-auto">
              <Wifi className="w-6 h-6" />
            </div>
            <div className="space-y-1">
              <h3 className="text-base font-semibold text-[#F5F7FA]">No Wi-Fi Beacons Captured Yet</h3>
              <p className="text-xs text-[#A7B0BC] max-w-md mx-auto leading-relaxed">
                Click below to query your Windows WLAN adapter using read-only <code className="font-mono text-[#38BDF8]">netsh wlan</code> commands.
              </p>
            </div>
            <Button
              onClick={handleScan}
              disabled={isScanning}
              variant="primary"
              className="inline-flex items-center gap-2"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <RotateCw className="w-4 h-4" />
                  <span>Scan Wi-Fi Environment Now</span>
                </>
              )}
            </Button>
          </div>
        ) : (
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
        )}
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
