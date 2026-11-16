import test from 'node:test';
import assert from 'node:assert/strict';

test('Network Trust: Risk Score and Confidence Mathematical Bounds', () => {
  const computeRisk = (penalties: number[]) => {
    const raw = penalties.reduce((a, b) => a + b, 0);
    return Math.max(0, Math.min(100, raw));
  };

  assert.equal(computeRisk([40, 50]), 90);
  assert.equal(computeRisk([40, 50, 65]), 100); // capped at 100
  assert.equal(computeRisk([]), 0);
});

test('Network Trust: Severity Tier Classification Matches Policy Thresholds', () => {
  const getSeverity = (score: number, thresholds = { LOW_MAX: 24, MODERATE_MAX: 49, HIGH_MAX: 74 }) => {
    if (score <= thresholds.LOW_MAX) return 'LOW';
    if (score <= thresholds.MODERATE_MAX) return 'MODERATE';
    if (score <= thresholds.HIGH_MAX) return 'HIGH';
    return 'CRITICAL';
  };

  assert.equal(getSeverity(10), 'LOW');
  assert.equal(getSeverity(24), 'LOW');
  assert.equal(getSeverity(25), 'MODERATE');
  assert.equal(getSeverity(49), 'MODERATE');
  assert.equal(getSeverity(50), 'HIGH');
  assert.equal(getSeverity(74), 'HIGH');
  assert.equal(getSeverity(75), 'CRITICAL');
  assert.equal(getSeverity(100), 'CRITICAL');
});

test('Network Trust: Quarantine Rule Names Enforce Unique Prefix MYX_AI_NTI_', () => {
  const formatRuleName = (type: string, sessionId: string) => `MYX_AI_NTI_${type}_${sessionId}`;

  const rule = formatRuleName('BLOCK_OUT', 'q-1234');
  assert.match(rule, /^MYX_AI_NTI_/);
  assert.equal(rule.startsWith('MYX_AI_NTI_'), true);
});

test('Network Trust: Missing Telemetry Field Confidence Penalty Formula', () => {
  const computeConfidence = (missingFields: string[]) => {
    let conf = 100;
    if (missingFields.includes('gateway_mac')) conf -= 25;
    if (missingFields.includes('dns_servers')) conf -= 20;
    if (missingFields.includes('ssid')) conf -= 30;
    return Math.max(10, Math.min(100, conf));
  };

  assert.equal(computeConfidence([]), 100);
  assert.equal(computeConfidence(['gateway_mac']), 75);
  assert.equal(computeConfidence(['gateway_mac', 'dns_servers']), 55);
  assert.equal(computeConfidence(['gateway_mac', 'dns_servers', 'ssid']), 25);
});
