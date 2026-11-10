/**
 * WebShield - Unit Tests for Feature Extraction and Rule Evaluation
 *
 * Uses built-in Node.js `assert` module.
 * Evaluates obviously safe synthetic URLs vs. fake phishing-style synthetic URLs
 * built entirely on example.com and RFC 2606 reserved domains (never real malicious domains).
 */

const assert = require('assert');
const path = require('path');

const { extractFeatures } = require('../extension/lib/features.js');
const { evaluateRules } = require('../extension/lib/rules.js');

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
console.log(' WebShield Test Suite: URL Feature Extraction & Rule Engine');
console.log('============================================================\n');

// ---------------------------------------------------------------------------
// Suite 1: Feature Extraction Accuracy
// ---------------------------------------------------------------------------
console.log('--- Suite 1: Feature Extraction Accuracy ---');

runTest('Extracts basic features correctly from a clean HTTPS URL', () => {
  const url = 'https://example.com/docs/guide';
  const f = extractFeatures(url);

  assert.strictEqual(f.isHttps, true);
  assert.strictEqual(f.hostnameLength, 11);
  assert.strictEqual(f.isIpAddress, false);
  assert.strictEqual(f.hasAtSymbol, false);
  assert.strictEqual(f.hasPunycodeOrNonAscii, false);
  assert.strictEqual(f.suspiciousTld, null);
  assert.strictEqual(f.subdomainCount, 0);
  assert.strictEqual(f.pathDepth, 2);
  assert.deepStrictEqual(f.brandKeywordsFound, []);
});

runTest('Detects raw IPv4 host correctly', () => {
  const url = 'http://192.168.1.1:8080/index.html';
  const f = extractFeatures(url);

  assert.strictEqual(f.isIpAddress, true);
  assert.strictEqual(f.isHttps, false);
  assert.strictEqual(f.dotCount, 4); // 3 in IPv4 + 1 in .html
});

runTest('Detects @ symbol in URL', () => {
  const url = 'https://example.com@fake-host.example.org/test';
  const f = extractFeatures(url);

  assert.strictEqual(f.hasAtSymbol, true);
});

runTest('Detects Punycode in host (homograph vector)', () => {
  const url = 'https://xn--e1afmkfd.example.com/';
  const f = extractFeatures(url);

  assert.strictEqual(f.hasPunycodeOrNonAscii, true);
});

runTest('Detects suspicious TLD (.xyz)', () => {
  const url = 'https://portal.example.xyz/dashboard';
  const f = extractFeatures(url);

  assert.strictEqual(f.suspiciousTld, '.xyz');
});

runTest('Detects brand keywords outside root domain', () => {
  const url = 'https://paypal.account-update.example.com/login';
  const f = extractFeatures(url);

  assert.ok(f.brandKeywordsFound.includes('paypal'), 'Should detect paypal keyword');
  assert.ok(f.brandKeywordsFound.includes('login'), 'Should detect login keyword');
  assert.strictEqual(f.subdomainCount, 2);
});

runTest('Computes path depth accurately', () => {
  const url = 'https://example.com/one/two/three/four/five';
  const f = extractFeatures(url);

  assert.strictEqual(f.pathDepth, 5);
});

// ---------------------------------------------------------------------------
// Suite 2: Obviously Safe URLs (Benign Baseline)
// ---------------------------------------------------------------------------
console.log('\n--- Suite 2: Obviously Safe URLs (Benign Baseline) ---');

const safeUrls = [
  'https://example.com/',
  'https://sub.example.com/about/team',
  'https://example.org/docs/api/v1',
  'https://dev.example.net/search?q=open+source'
];

safeUrls.forEach((url) => {
  runTest(`Safe URL evaluation: ${url}`, () => {
    const f = extractFeatures(url);
    const r = evaluateRules(f);

    console.log(`         Score: ${r.score} | Verdict: ${r.verdict}`);
    assert.strictEqual(r.verdict, 'SAFE', `Expected SAFE for ${url}`);
    assert.ok(r.score < 0.35, `Score should be below 0.35 for safe URL (got ${r.score})`);
  });
});

// ---------------------------------------------------------------------------
// Suite 3: Fake Phishing-Style Synthetic URLs
// (Built purely on example.com / fake reserved domains - never real malicious domains)
// ---------------------------------------------------------------------------
console.log('\n--- Suite 3: Fake Phishing-Style Synthetic URLs ---');

const suspiciousUrls = [
  {
    desc: 'Raw IP address host with HTTP and login path',
    url: 'http://192.168.1.100/login',
    expectedVerdict: 'HIGH_RISK',
    expectedReasonSnippet: 'raw IP address'
  },
  {
    desc: 'Multiple brand keywords in subdomain + suspicious .xyz TLD + deep path',
    url: 'https://paypal.secure-verification.example.xyz/account/login/verify',
    expectedVerdict: 'HIGH_RISK',
    expectedReasonSnippet: 'frequently abused top-level domain'
  },
  {
    desc: 'Authority obfuscation via @ symbol with suspicious .top TLD',
    url: 'http://example.com@phish-gateway.example.top/verify',
    expectedVerdict: 'HIGH_RISK',
    expectedReasonSnippet: "@' symbol"
  },
  {
    desc: 'Punycode homograph domain with bank keyword in path',
    url: 'https://xn--pple-43d.example.com/bank/verify',
    expectedVerdict: 'HIGH_RISK',
    expectedReasonSnippet: 'Punycode'
  },
  {
    desc: 'Combosquatting hyphens + .click TLD + multiple subdomains + high digit ratio',
    url: 'http://secure-login-account-update-bank.sub1.sub2.example.click/9876543210/confirm',
    expectedVerdict: 'HIGH_RISK',
    expectedReasonSnippet: 'Excessive hyphens'
  }
];

suspiciousUrls.forEach(({ desc, url, expectedVerdict, expectedReasonSnippet }) => {
  runTest(`Suspicious URL: ${desc}`, () => {
    const f = extractFeatures(url);
    const r = evaluateRules(f);

    console.log(`         URL: ${url}`);
    console.log(`         Score: ${r.score} | Verdict: ${r.verdict}`);
    console.log(`         Reasons: ${JSON.stringify(r.reasons)}`);

    assert.strictEqual(r.verdict, expectedVerdict, `Expected ${expectedVerdict} for ${url}`);
    assert.ok(r.score >= 0.70, `Score should be >= 0.70 (got ${r.score})`);
    assert.ok(
      r.reasons.some(reason => reason.toLowerCase().includes(expectedReasonSnippet.toLowerCase())),
      `Expected reasons to mention "${expectedReasonSnippet}"`
    );
  });
});

// ---------------------------------------------------------------------------
// Suite 4: Secure Contexts (Localhost & 127.0.0.1)
// ---------------------------------------------------------------------------
console.log('--- Suite 4: Secure Contexts (Localhost & Loopback) ---');

runTest('Localhost and 127.0.0.1 treated as secure (no insecure HTTP finding)', () => {
  const fLocal = extractFeatures('http://localhost:8080/dashboard');
  const rLocal = evaluateRules(fLocal);
  assert.strictEqual(
    rLocal.reasons.some(r => r.includes('Insecure connection')),
    false,
    'localhost should not have insecure HTTP finding'
  );

  const fIp = extractFeatures('http://127.0.0.1:3000/app');
  const rIp = evaluateRules(fIp);
  assert.strictEqual(
    rIp.reasons.some(r => r.includes('Insecure connection')),
    false,
    '127.0.0.1 should not have insecure HTTP finding'
  );
});

// ---------------------------------------------------------------------------
// Final Summary
// ---------------------------------------------------------------------------
console.log('\n============================================================');
console.log(` Results: ${passedTests}/${totalTests} tests passed.`);
console.log('============================================================\n');

if (passedTests !== totalTests) {
  process.exit(1);
}
