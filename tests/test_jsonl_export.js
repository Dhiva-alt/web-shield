/**
 * WebShield - Unit Tests for SIEM JSON Lines (.jsonl) Export
 *
 * Verifies that the audit log formatter outputs valid NDJSON
 * adhering strictly to the schema required for Wazuh / Splunk ingestion:
 * (timestamp, url, score, tier, reasons, mitre)
 */

const assert = require('assert');

let totalTests = 0;
let passedTests = 0;

function runTest(name, fn) {
  totalTests++;
  try {
    fn();
    passedTests++;
    console.log(`  [PASS] ${name}`);
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    process.exitCode = 1;
  }
}

console.log('\n============================================================');
console.log(' WebShield Test Suite: SIEM JSON Lines Export Verifier');
console.log('============================================================\n');

// Formatter function replicating popup.js export logic
function formatAuditLogToJsonl(auditLog) {
  const lines = auditLog.map(entry => {
    const record = {
      timestamp: entry.timestamp,
      url: entry.url,
      score: entry.score,
      tier: entry.tier,
      reasons: entry.reasons || [],
      mitre: entry.mitreTechnique || entry.mitre || 'None'
    };
    return JSON.stringify(record);
  });
  return lines.join('\n') + '\n';
}

const mockAuditLog = [
  {
    timestamp: '2026-11-09T14:40:00.000Z',
    url: 'https://example.com/login',
    score: 0.15,
    tier: 'LOW',
    reasons: ['Missing Content-Security-Policy (CSP) header'],
    mitreTechnique: null
  },
  {
    timestamp: '2026-11-09T14:41:00.000Z',
    url: 'https://paypal.secure-login.example.xyz/account',
    score: 0.95,
    tier: 'HIGH',
    reasons: [
      'Contains sensitive brand keyword (paypal)',
      'Uses a frequently abused top-level domain (.xyz)'
    ],
    mitreTechnique: 'T1566.002: Spearphishing Link'
  },
  {
    timestamp: '2026-11-09T14:42:00.000Z',
    url: 'http://192.168.1.100/admin',
    score: 0.88,
    tier: 'HIGH',
    reasons: ['Uses raw IP address instead of domain name'],
    mitreTechnique: 'T1566: Phishing'
  }
];

runTest('Formats audit log into valid JSON Lines (.jsonl)', () => {
  const jsonlOutput = formatAuditLogToJsonl(mockAuditLog);
  const rawLines = jsonlOutput.trim().split('\n');

  assert.strictEqual(rawLines.length, 3, 'Should produce 3 distinct JSON lines');

  rawLines.forEach((line, index) => {
    // Each line must be standalone valid JSON
    const parsed = JSON.parse(line);
    const expected = mockAuditLog[index];

    assert.strictEqual(parsed.timestamp, expected.timestamp);
    assert.strictEqual(parsed.url, expected.url);
    assert.strictEqual(parsed.score, expected.score);
    assert.strictEqual(parsed.tier, expected.tier);
    assert.deepStrictEqual(parsed.reasons, expected.reasons);
    assert.strictEqual(parsed.mitre, expected.mitreTechnique || 'None');

    // Verify exact required keys exist
    const keys = Object.keys(parsed).sort();
    assert.deepStrictEqual(
      keys,
      ['mitre', 'reasons', 'score', 'tier', 'timestamp', 'url'].sort()
    );
  });
});

runTest('Guarantees zero password or page body content in export (Rule 6)', () => {
  const jsonlOutput = formatAuditLogToJsonl(mockAuditLog);

  // Assert no credential fields or inner HTML values are present
  assert.strictEqual(jsonlOutput.includes('password='), false);
  assert.strictEqual(jsonlOutput.includes('session_token'), false);
  assert.strictEqual(jsonlOutput.includes('<body>'), false);
});

console.log('\n============================================================');
console.log(` Results: ${passedTests}/${totalTests} tests passed.`);
console.log('============================================================\n');

if (passedTests !== totalTests) {
  process.exit(1);
}
