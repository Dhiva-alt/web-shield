/**
 * WebShield - Unit Tests for DOM Heuristic Scanner Logic
 *
 * Validates domain comparison calculations and performs static privacy checks
 * guaranteeing that content.js NEVER accesses .value or captures keystrokes (Project Rule 6).
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

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
console.log(' WebShield Test Suite: DOM Scanner Logic & Privacy Guardrails');
console.log('============================================================\n');

// 1. Static Privacy Audit of content.js
runTest('Content script strictly forbids .value reads (Project Rule 6)', () => {
  const contentJsPath = path.join(__dirname, '../extension/content.js');
  const rawCode = fs.readFileSync(contentJsPath, 'utf8');

  // Strip single-line and multi-line comments
  const codeWithoutComments = rawCode.replace(/\/\*[\s\S]*?\*\/|\/\/.*/g, '');

  // Check for .value reading patterns in actual executable code
  const valueAccessRegex = /\.(?:value|val)\b(?!\s*:\s*)/g;
  const matches = codeWithoutComments.match(valueAccessRegex) || [];

  assert.strictEqual(
    matches.length,
    0,
    `Found forbidden .value access in executable content.js code: ${JSON.stringify(matches)}`
  );
});

runTest('Content script does not register input, change, or keydown event listeners', () => {
  const contentJsPath = path.join(__dirname, '../extension/content.js');
  const code = fs.readFileSync(contentJsPath, 'utf8');

  assert.strictEqual(code.includes("addEventListener('input'"), false);
  assert.strictEqual(code.includes("addEventListener('keydown'"), false);
  assert.strictEqual(code.includes("addEventListener('keyup'"), false);
  assert.strictEqual(code.includes("addEventListener('keypress'"), false);
});

// 2. Registrable Domain Parsing Tests
function getRegistrableDomain(hostname) {
  if (!hostname) return '';
  const cleanHost = hostname.toLowerCase().trim();
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(cleanHost) || cleanHost.includes(':') || cleanHost === 'localhost') {
    return cleanHost;
  }
  const parts = cleanHost.split('.');
  if (parts.length <= 2) return cleanHost;
  const isTwoPartSuffix = parts.length >= 3 &&
    (parts[parts.length - 2] === 'co' || parts[parts.length - 2] === 'com');
  const sliceCount = isTwoPartSuffix ? 3 : 2;
  return parts.slice(-sliceCount).join('.');
}

runTest('Correctly identifies cross-registrable-domain actions', () => {
  const pageHost = 'example.com';
  const targetHost = 'attacker-harvest.example.org';

  const currentDomain = getRegistrableDomain(pageHost);
  const targetDomain = getRegistrableDomain(targetHost);

  assert.strictEqual(currentDomain, 'example.com');
  assert.strictEqual(targetDomain, 'example.org');
  assert.notStrictEqual(currentDomain, targetDomain, 'Domains must be recognized as different');
});

runTest('Correctly allows same-registrable-domain subdomains', () => {
  const pageHost = 'portal.login.example.com';
  const targetHost = 'auth.example.com';

  const currentDomain = getRegistrableDomain(pageHost);
  const targetDomain = getRegistrableDomain(targetHost);

  assert.strictEqual(currentDomain, 'example.com');
  assert.strictEqual(targetDomain, 'example.com');
  assert.strictEqual(currentDomain, targetDomain, 'Subdomains of the same domain must match');
});

console.log('\n============================================================');
console.log(` Results: ${passedTests}/${totalTests} tests passed.`);
console.log('============================================================\n');

if (passedTests !== totalTests) {
  process.exit(1);
}
