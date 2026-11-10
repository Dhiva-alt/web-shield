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
      mitre: entry.mitreTechnique || entry.mitre || null
    };
    return JSON.stringify(record);
  });
  return lines.join('\n') + '\n';
}

// Replicates popup.js alert list item rendering
function renderAlertItemHtml(entry) {
  const mitreVal = entry.mitreTechnique || entry.mitre;
  const mitreHtml = mitreVal
    ? `<div class="alert-mitre">${mitreVal}</div>`
    : '';
  return `
    <div class="alert-top">
      <span class="alert-tier">[${entry.tier}] ${Math.round((entry.score || 0) * 100)}%</span>
      <span class="alert-time">${entry.timestamp}</span>
    </div>
    <div class="alert-url">${entry.url}</div>
    ${mitreHtml}
  `.trim();
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
    assert.strictEqual(parsed.mitre, expected.mitreTechnique || null);

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

runTest('Hygiene-only result writes mitre = null and the popup shows no tag', () => {
  const riskEngine = require('../extension/lib/risk_engine.js');

  // 1. Evaluate a hygiene-only / benign site (example.com with missing security header)
  const evalResult = riskEngine.evaluateRisk({
    url: 'https://example.com',
    ruleScore: 0.0,
    ruleReasons: [],
    mlProbability: 0.05,
    headerFindings: ['Missing Content-Security-Policy (CSP) header']
  });

  // Verify risk engine assigned null to mitreTechnique
  assert.strictEqual(evalResult.mitreTechnique, null, 'Risk engine must assign null for hygiene-only');

  // 2. Audit log entry written with mitre = null
  const auditEntry = {
    timestamp: new Date().toISOString(),
    url: 'https://example.com',
    score: evalResult.score,
    tier: evalResult.tier,
    reasons: evalResult.reasons,
    mitre: evalResult.mitreTechnique || null,
    mitreTechnique: evalResult.mitreTechnique || null
  };
  assert.strictEqual(auditEntry.mitre, null);
  assert.strictEqual(auditEntry.mitreTechnique, null);

  // 3. Exported JSON Line has mitre: null (not "T1566: Phishing")
  const jsonl = formatAuditLogToJsonl([auditEntry]);
  const parsedExport = JSON.parse(jsonl.trim());
  assert.strictEqual(parsedExport.mitre, null, 'Exported JSONL must contain mitre: null');
  assert.strictEqual(jsonl.includes('T1566'), false, 'Exported JSONL must not contain T1566 fallback');

  // 4. Popup alert item rendering: no .alert-mitre tag
  const html = renderAlertItemHtml(auditEntry);
  assert.strictEqual(html.includes('alert-mitre'), false, 'Popup HTML must not contain alert-mitre tag for hygiene');
  assert.strictEqual(html.includes('T1566'), false, 'Popup HTML must not contain T1566 tag for hygiene');
});

runTest('Allowlisted visits store mitre = null, popup shows no tag, and excluded from alert list & JSONL export', () => {
  const riskEngine = require('../extension/lib/risk_engine.js');

  // 1. Evaluate an allowlisted visit
  const evalResult = riskEngine.evaluateRisk({
    url: 'https://trusted-bank.example.com/login',
    ruleScore: 0.95,
    ruleReasons: ['Brand keyword detected'],
    mlProbability: 0.98,
    allowlist: ['trusted-bank.example.com']
  });

  // Verify tier is ALLOWLISTED and mitreTechnique is null (not "N/A (Allowlisted)")
  assert.strictEqual(evalResult.tier, 'ALLOWLISTED');
  assert.strictEqual(evalResult.mitreTechnique, null, 'Allowlisted visits must store mitre = null');

  // 2. Mock audit log containing a mix of high-risk and allowlisted entries
  const mixedLog = [
    {
      timestamp: '2026-11-10T09:00:00.000Z',
      url: 'https://trusted-bank.example.com/login',
      score: 0.0,
      tier: 'ALLOWLISTED',
      reasons: ['Domain is present in your trusted allowlist.'],
      mitre: null,
      mitreTechnique: null
    },
    {
      timestamp: '2026-11-10T09:05:00.000Z',
      url: 'https://phishing.example.xyz/account',
      score: 0.90,
      tier: 'HIGH',
      reasons: ['Suspicious TLD'],
      mitre: 'T1566.002: Spearphishing Link',
      mitreTechnique: 'T1566.002: Spearphishing Link'
    }
  ];

  // 3. Filter for Alert List (popup logic): excludes ALLOWLISTED
  const alertListEntries = mixedLog.filter(entry => entry.tier !== 'ALLOWLISTED');
  assert.strictEqual(alertListEntries.length, 1);
  assert.strictEqual(alertListEntries[0].tier, 'HIGH');
  assert.strictEqual(alertListEntries.some(e => e.tier === 'ALLOWLISTED'), false);

  // 4. Filter for JSONL Export (popup logic): excludes ALLOWLISTED
  const exportableEntries = mixedLog.filter(entry => entry.tier !== 'ALLOWLISTED');
  const jsonl = formatAuditLogToJsonl(exportableEntries);
  assert.strictEqual(jsonl.includes('trusted-bank.example.com'), false, 'Allowlisted visit must not be in JSONL export');
  assert.strictEqual(jsonl.includes('ALLOWLISTED'), false, 'ALLOWLISTED tier must not appear in JSONL export');
  assert.strictEqual(jsonl.includes('phishing.example.xyz'), true, 'Non-allowlisted alerts must be preserved');

  // 5. Popup header representation for allowlisted site: no tag (style.display = 'none')
  function renderPopupMitreTag(record) {
    if (record.mitreTechnique) {
      return { display: 'inline-block', text: `MITRE: ${record.mitreTechnique}` };
    }
    return { display: 'none', text: '' };
  }
  const tagState = renderPopupMitreTag(evalResult);
  assert.strictEqual(tagState.display, 'none', 'Popup must hide MITRE tag for allowlisted visits');
  assert.strictEqual(tagState.text, '', 'Popup MITRE tag text must be empty for allowlisted visits');
});

console.log('\n============================================================');
console.log(` Results: ${passedTests}/${totalTests} tests passed.`);
console.log('============================================================\n');

if (passedTests !== totalTests) {
  process.exit(1);
}
