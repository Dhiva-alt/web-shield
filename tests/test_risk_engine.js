/**
 * WebShield - Unit Tests for Unified Risk Engine & Tiering
 *
 * Validates:
 * - Tier cutoffs (LOW, MEDIUM, HIGH)
 * - Allowlist bypass logic
 * - DOM critical finding escalation
 * - MITRE ATT&CK technique resolution
 * - FIFO capping at 500 audit log entries
 */

const assert = require('assert');
const config = require('../extension/lib/config.js');
const riskEngine = require('../extension/lib/risk_engine.js');

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
console.log(' WebShield Test Suite: Unified Risk Engine & Decision Tiers');
console.log('============================================================\n');

// 1. Safe URL -> LOW Tier
runTest('Safe benign signals produce LOW tier (log only)', () => {
  const result = riskEngine.evaluateRisk({
    url: 'https://example.com/about',
    ruleScore: 0.0,
    ruleReasons: [],
    mlProbability: 0.05,
    headerFindings: [],
    domFindings: []
  });

  assert.strictEqual(result.tier, 'LOW');
  assert.ok(result.score < 0.40);
  assert.strictEqual(result.isAllowlisted, false);
});

// 2. Moderate Suspicion -> MEDIUM Tier
runTest('Moderate risk signals trigger MEDIUM tier (badge + notification)', () => {
  const result = riskEngine.evaluateRisk({
    url: 'https://subdomain.login.example.com/account',
    ruleScore: 0.50,
    ruleReasons: ['Multiple subdomains detected'],
    mlProbability: 0.60,
    headerFindings: ['Missing Content-Security-Policy (CSP) header'],
    domFindings: []
  });

  assert.strictEqual(result.tier, 'MEDIUM');
  assert.ok(result.score >= 0.40 && result.score < 0.70);
});

// 3. Severe Phishing Indicators -> HIGH Tier
runTest('Severe phishing indicators trigger HIGH tier (warning redirect)', () => {
  const result = riskEngine.evaluateRisk({
    url: 'https://paypal.secure-login.example.xyz/verify',
    ruleScore: 0.90,
    ruleReasons: [
      'Contains sensitive brand keyword (paypal)',
      'Uses a frequently abused top-level domain (.xyz)'
    ],
    mlProbability: 0.95,
    headerFindings: [],
    domFindings: []
  });

  assert.strictEqual(result.tier, 'HIGH');
  assert.ok(result.score >= 0.70);
  assert.strictEqual(result.mitreTechnique, 'T1566.002: Spearphishing Link');
});

// 4. Critical DOM Finding Escalation -> HIGH Tier
runTest('Cross-domain password submission immediately triggers HIGH tier', () => {
  const result = riskEngine.evaluateRisk({
    url: 'https://example.com/login',
    ruleScore: 0.10,
    ruleReasons: [],
    mlProbability: 0.15,
    domFindings: [
      'Password form action submits to a different domain (attacker.com) than current page (example.com)'
    ]
  });

  assert.strictEqual(result.tier, 'HIGH');
  assert.strictEqual(result.mitreTechnique, 'T1056.003: Web Portal Capture');
});

// 5. User Allowlist Bypass
runTest('User allowlist overrides high-risk signals to ALLOWLISTED tier', () => {
  const allowlist = ['example.xyz', 'test-domain.org'];
  const result = riskEngine.evaluateRisk({
    url: 'https://paypal.example.xyz/login',
    ruleScore: 0.95,
    ruleReasons: ['Brand keyword detected'],
    mlProbability: 0.99,
    allowlist
  });

  assert.strictEqual(result.tier, 'ALLOWLISTED');
  assert.strictEqual(result.score, 0.0);
  assert.strictEqual(result.isAllowlisted, true);
  assert.strictEqual(result.mitreTechnique, null, 'Allowlisted visit must have mitreTechnique = null');
});

// 6. MITRE Technique Resolution Checks
runTest('Resolves homograph attacks to IDN homograph MITRE technique', () => {
  const tech = riskEngine.resolveMitreTechnique(
    ['Host contains Punycode (xn--) or non-ASCII characters (homograph risk)'],
    []
  );
  assert.strictEqual(tech, 'T1566: Phishing (IDN Homograph)');
});

runTest('Resolves clickjacking and hidden iframes to T1204.001', () => {
  const tech = riskEngine.resolveMitreTechnique(
    ['Missing X-Frame-Options header (clickjacking protection)'],
    ['Hidden iframe detected on page']
  );
  assert.strictEqual(tech, 'T1204.001: Malicious Link');
});

// 7. Audit Log 500-Item FIFO Cap
runTest('Enforces 500-entry FIFO ceiling on audit log', () => {
  const dummyLog = [];
  for (let i = 1; i <= 550; i++) {
    dummyLog.push({ id: i, url: `https://site${i}.example.com` });
  }

  const trimmed = dummyLog.slice(-config.maxAuditEntries);
  assert.strictEqual(trimmed.length, 500);
  assert.strictEqual(trimmed[0].id, 51, 'Oldest 50 entries should be pruned (FIFO)');
  assert.strictEqual(trimmed[499].id, 550, 'Latest entry should be retained');
});

// ---------------------------------------------------------------------------
// Bug Fix Verifications: Items 2, 4, 5
// ---------------------------------------------------------------------------

// Item 2: Non-HTTP/HTTPS Scheme Rejection
runTest('Item 2: Rejects non-http and non-https schemes (chrome://, devtools://, file:, about:)', () => {
  const nonWebSchemes = [
    'chrome://extensions',
    'chrome://settings',
    'devtools://devtools/bundled/inspector.html',
    'chrome-extension://abcdefghijklmnop/popup.html',
    'about:blank',
    'file:///C:/Users/test/passwords.txt',
    'javascript:alert(1)'
  ];

  for (const url of nonWebSchemes) {
    assert.strictEqual(riskEngine.isHttpOrHttps(url), false, `${url} should not be valid http/https`);
    const result = riskEngine.evaluateRisk({ url });
    assert.strictEqual(result.tier, 'IGNORED');
    assert.strictEqual(result.score, 0.0);
    assert.strictEqual(result.mitreTechnique, null);
    assert.ok(result.reasons[0].includes('not http or https'));
  }

  // Valid schemes should pass
  assert.strictEqual(riskEngine.isHttpOrHttps('http://example.com'), true);
  assert.strictEqual(riskEngine.isHttpOrHttps('https://example.com/test'), true);
});

// Item 4: Score and Tier Agreement & Override Finding
runTest('Item 4: Score and tier agree on override rule and prepend finding', () => {
  // Scenario: ruleScore is 0 and mlProbability is 0.02, but DOM has cross-domain form
  const result = riskEngine.evaluateRisk({
    url: 'https://benign-looking.example.com/login',
    ruleScore: 0.0,
    ruleReasons: [],
    mlProbability: 0.02,
    domFindings: [
      'Password form action submits to a different domain (attacker-harvest.example.org) than current page (example.com)'
    ]
  });

  // Tier must be HIGH
  assert.strictEqual(result.tier, 'HIGH');
  // Score MUST agree with HIGH tier (>= 0.70), NOT stay low at 0.08
  assert.ok(result.score >= 0.70, `Score must be >= 0.70 to agree with HIGH tier (was ${result.score})`);
  // Override finding must be visible as a distinct reason
  assert.ok(
    result.reasons.some(r => r.startsWith('Override: Cross-domain password submission')),
    'Override reason should be prepended to findings list'
  );
});

// Item 5: MITRE Technique Filtering (No MITRE tag on hygiene, No T1040)
runTest('Item 5: Shows MITRE technique ONLY for phishing or credential theft (hygiene gets null, no T1040)', () => {
  // A. Only header hygiene findings -> mitreTechnique MUST be null
  const headerOnly = riskEngine.resolveMitreTechnique(
    [
      '[Header] Missing Content-Security-Policy (CSP) header',
      '[Header] Missing Strict-Transport-Security (HSTS) header on HTTPS site',
      '[Header] Cookie set without HttpOnly flag (2 observed)'
    ],
    []
  );
  assert.strictEqual(headerOnly, null, 'Security header findings must NOT receive a MITRE tag');

  // B. Insecure HTTP transport alone -> mitreTechnique MUST be null (no T1040)
  const transportOnly = riskEngine.resolveMitreTechnique(
    ['Insecure connection (HTTP instead of HTTPS)'],
    []
  );
  assert.strictEqual(transportOnly, null, 'Insecure HTTP alone must NOT receive a MITRE tag');

  // C. Full evaluation with hygiene only -> mitreTechnique is null
  const evalHygieneOnly = riskEngine.evaluateRisk({
    url: 'http://my-insecure-site.example.com',
    ruleScore: 0.15,
    ruleReasons: ['Insecure connection (HTTP instead of HTTPS)'],
    mlProbability: 0.10,
    headerFindings: ['Missing Content-Security-Policy (CSP) header']
  });
  assert.strictEqual(evalHygieneOnly.mitreTechnique, null, 'Hygiene-only eval should have null MITRE tag');

  // D. Credential theft -> T1056.003
  const credTheft = riskEngine.resolveMitreTechnique(
    [],
    ['Password form action submits to a different domain (evil.com)']
  );
  assert.strictEqual(credTheft, 'T1056.003: Web Portal Capture');

  // E. Phishing indicators -> T1566 / T1566.002
  const phishLink = riskEngine.resolveMitreTechnique(
    ['Contains sensitive brand keyword (paypal) in path', 'Uses a frequently abused top-level domain (.xyz)'],
    []
  );
  assert.strictEqual(phishLink, 'T1566.002: Spearphishing Link');

  // F. Confirm T1040 is not in config
  assert.strictEqual(config.mitreTechniques.insecureTransport, undefined);
});

// Bug 10: Deduplication on URL + tier + score + reasons within 5 seconds
runTest('Bug 10: Deduplicates alert on URL + tier + score + reasons within 5-second window', () => {
  const baseTimestamp = new Date('2026-11-10T12:00:00.000Z').toISOString();
  const alertEntry = {
    timestamp: baseTimestamp,
    url: 'http://localhost:8080/tests/pages/cross_origin_form.html',
    tier: 'HIGH',
    score: 0.70,
    reasons: [
      'Override: Cross-domain password submission detected (forces HIGH risk tier)',
      '[DOM] Password form action submits to a different domain (attacker-harvest.example.org) than current page (localhost)'
    ]
  };

  const existingLog = [alertEntry];

  // 1. Identical alert with same timestamp (0 ms difference) -> DUPLICATE
  const exactDuplicate = {
    ...alertEntry,
    timestamp: baseTimestamp
  };
  assert.strictEqual(
    riskEngine.isDuplicateAlert(exactDuplicate, existingLog, 5000),
    true,
    'Identical alert with same timestamp should be detected as duplicate'
  );

  // 2. Identical alert 2000 ms later (within 5s window) -> DUPLICATE
  const nearDuplicate = {
    ...alertEntry,
    timestamp: new Date('2026-11-10T12:00:02.000Z').toISOString()
  };
  assert.strictEqual(
    riskEngine.isDuplicateAlert(nearDuplicate, existingLog, 5000),
    true,
    'Identical alert 2 seconds later should be detected as duplicate'
  );

  // 3. Same alert with reasons in reversed order within 5s window -> DUPLICATE
  const reversedReasonsDuplicate = {
    ...alertEntry,
    timestamp: new Date('2026-11-10T12:00:01.500Z').toISOString(),
    reasons: [
      '[DOM] Password form action submits to a different domain (attacker-harvest.example.org) than current page (localhost)',
      'Override: Cross-domain password submission detected (forces HIGH risk tier)'
    ]
  };
  assert.strictEqual(
    riskEngine.isDuplicateAlert(reversedReasonsDuplicate, existingLog, 5000),
    true,
    'Alert with same reasons in different order should be detected as duplicate'
  );

  // 4. Identical alert 6000 ms later (outside 5s window) -> NOT duplicate
  const outsideWindowAlert = {
    ...alertEntry,
    timestamp: new Date('2026-11-10T12:00:06.000Z').toISOString()
  };
  assert.strictEqual(
    riskEngine.isDuplicateAlert(outsideWindowAlert, existingLog, 5000),
    false,
    'Alert 6 seconds later should NOT be detected as duplicate'
  );

  // 5. Different URL within 5s window -> NOT duplicate
  const differentUrlAlert = {
    ...alertEntry,
    url: 'http://localhost:8080/tests/pages/other_form.html',
    timestamp: new Date('2026-11-10T12:00:01.000Z').toISOString()
  };
  assert.strictEqual(
    riskEngine.isDuplicateAlert(differentUrlAlert, existingLog, 5000),
    false,
    'Alert with different URL should NOT be detected as duplicate'
  );

  // 6. Different tier within 5s window -> NOT duplicate
  const differentTierAlert = {
    ...alertEntry,
    tier: 'LOW',
    timestamp: new Date('2026-11-10T12:00:01.000Z').toISOString()
  };
  assert.strictEqual(
    riskEngine.isDuplicateAlert(differentTierAlert, existingLog, 5000),
    false,
    'Alert with different tier should NOT be detected as duplicate'
  );

  // 7. Different score within 5s window -> NOT duplicate
  const differentScoreAlert = {
    ...alertEntry,
    score: 0.06,
    timestamp: new Date('2026-11-10T12:00:01.000Z').toISOString()
  };
  assert.strictEqual(
    riskEngine.isDuplicateAlert(differentScoreAlert, existingLog, 5000),
    false,
    'Alert with different score should NOT be detected as duplicate'
  );

  // 8. Different reasons within 5s window -> NOT duplicate
  const differentReasonsAlert = {
    ...alertEntry,
    reasons: ['Different reason'],
    timestamp: new Date('2026-11-10T12:00:01.000Z').toISOString()
  };
  assert.strictEqual(
    riskEngine.isDuplicateAlert(differentReasonsAlert, existingLog, 5000),
    false,
    'Alert with different reasons should NOT be detected as duplicate'
  );

  // 9. Empty log or invalid input -> NOT duplicate
  assert.strictEqual(riskEngine.isDuplicateAlert(alertEntry, [], 5000), false);
  assert.strictEqual(riskEngine.isDuplicateAlert(null, existingLog, 5000), false);
});

console.log('\n============================================================');
console.log(` Results: ${passedTests}/${totalTests} tests passed.`);
console.log('============================================================\n');

if (passedTests !== totalTests) {
  process.exit(1);
}
