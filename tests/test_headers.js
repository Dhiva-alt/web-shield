/**
 * WebShield - Unit Tests for Security Headers Analyzer
 *
 * Uses built-in Node.js `assert` module.
 * Verifies detection of missing defensive headers and insecure cookie configurations
 * without storing or exposing credential/cookie payloads.
 */

const assert = require('assert');
const { inspectResponseHeaders } = require('../extension/lib/headers.js');

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
console.log(' WebShield Test Suite: HTTP Security Headers Analyzer');
console.log('============================================================\n');

runTest('Flags all missing defensive headers on bare HTTP response', () => {
  const headers = [
    { name: 'Content-Type', value: 'text/html; charset=UTF-8' }
  ];
  const url = 'http://example.com/';
  const result = inspectResponseHeaders(headers, url);

  assert.strictEqual(result.hostname, 'example.com');
  assert.strictEqual(result.severity, 'LOW');

  // Should flag CSP, XFO, XCTO (HSTS is skipped for plain http://)
  assert.ok(result.findings.some(f => f.includes('Content-Security-Policy')), 'Missing CSP');
  assert.ok(result.findings.some(f => f.includes('X-Frame-Options')), 'Missing XFO');
  assert.ok(result.findings.some(f => f.includes('X-Content-Type-Options')), 'Missing XCTO');
  assert.strictEqual(result.findings.some(f => f.includes('HSTS')), false, 'HSTS should not be flagged on HTTP');
});

runTest('Flags missing HSTS on HTTPS origin', () => {
  const headers = [
    { name: 'Content-Type', value: 'text/html' }
  ];
  const url = 'https://example.com/';
  const result = inspectResponseHeaders(headers, url);

  assert.ok(result.findings.some(f => f.includes('HSTS')), 'HSTS should be flagged on HTTPS');
});

runTest('Recognizes frame-ancestors in CSP as satisfying X-Frame-Options', () => {
  const headers = [
    { name: 'Content-Security-Policy', value: "default-src 'self'; frame-ancestors 'none';" },
    { name: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
    { name: 'X-Content-Type-Options', value: 'nosniff' }
  ];
  const url = 'https://example.com/';
  const result = inspectResponseHeaders(headers, url);

  assert.strictEqual(result.findings.length, 0, 'No findings expected for fully hardened origin');
});

runTest('Detects cookies missing HttpOnly and Secure flags without leaking values', () => {
  const secretSessionToken = 'SUPER_SECRET_SESSION_TOKEN_12345';
  const headers = [
    { name: 'Content-Security-Policy', value: "default-src 'self'" },
    { name: 'Strict-Transport-Security', value: 'max-age=31536000' },
    { name: 'X-Frame-Options', value: 'DENY' },
    { name: 'X-Content-Type-Options', value: 'nosniff' },
    { name: 'Set-Cookie', value: `session_id=${secretSessionToken}; Path=/; SameSite=Lax` }
  ];
  const url = 'https://example.com/login';
  const result = inspectResponseHeaders(headers, url);

  // Assert flags detected
  assert.ok(result.findings.some(f => f.includes('without HttpOnly flag')), 'Should detect missing HttpOnly');
  assert.ok(result.findings.some(f => f.includes('without Secure flag')), 'Should detect missing Secure');

  // CRITICAL PRIVACY ASSERTION: ensure token is NOT stored anywhere in result
  const serialized = JSON.stringify(result);
  assert.strictEqual(
    serialized.includes(secretSessionToken),
    false,
    'Confidential cookie value must NEVER be stored or present in output'
  );
  assert.strictEqual(
    serialized.includes('session_id'),
    false,
    'Cookie name should not be stored in output'
  );
});

runTest('Properly ignores cookies that have both Secure and HttpOnly flags', () => {
  const headers = [
    { name: 'Content-Security-Policy', value: "default-src 'self'" },
    { name: 'Strict-Transport-Security', value: 'max-age=31536000' },
    { name: 'X-Frame-Options', value: 'DENY' },
    { name: 'X-Content-Type-Options', value: 'nosniff' },
    { name: 'Set-Cookie', value: 'auth_token=xyz; Secure; HttpOnly; SameSite=Strict' }
  ];
  const url = 'https://example.com/';
  const result = inspectResponseHeaders(headers, url);

  assert.strictEqual(result.findings.length, 0, 'No findings expected for properly secured cookies');
});

console.log('\n============================================================');
console.log(` Results: ${passedTests}/${totalTests} tests passed.`);
console.log('============================================================\n');

if (passedTests !== totalTests) {
  process.exit(1);
}
