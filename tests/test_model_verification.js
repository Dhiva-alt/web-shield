/**
 * WebShield - Cross-Language Model Inference Verifier
 *
 * Compares in-browser JavaScript Random Forest predictions against
 * Python scikit-learn predictions on 20 test URLs.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const { extractFeatures } = require('../extension/lib/features.js');
const { predictProbability, buildFeatureVector } = require('../extension/lib/model.js');

const MODEL_PATH = path.join(__dirname, '../extension/model/rf_model.json');
const SAMPLES_PATH = path.join(__dirname, '../ml/outputs/sample_20_eval.json');

console.log('\n========================================================================');
console.log(' WebShield Verification: Random Forest Prediction Parity (JS vs. Python)');
console.log('========================================================================\n');

// 1. Verify JSON Model File Size
const stats = fs.statSync(MODEL_PATH);
const sizeBytes = stats.size;
const sizeKB = (sizeBytes / 1024).toFixed(2);
console.log(`[1] Checking extension/model/rf_model.json file size:`);
console.log(`    - Size: ${sizeBytes} bytes (${sizeKB} KB)`);
assert.ok(sizeBytes < 1024 * 1024, `Model JSON exceeds 1 MB limit (${sizeKB} KB)`);
console.log(`    - Status: PASSED (Under 1 MB threshold)\n`);

// 2. Load Model & Samples
const model = JSON.parse(fs.readFileSync(MODEL_PATH, 'utf8'));
const samples = JSON.parse(fs.readFileSync(SAMPLES_PATH, 'utf8'));

console.log(`[2] Evaluating 20 Sample Test URLs:`);
console.log('----------------------------------------------------------------------------------------------------------');
console.log(
  ' #  | Actual | Py Prob | JS Prob | Diff   | Match? | URL'
);
console.log('----------------------------------------------------------------------------------------------------------');

let allMatched = true;
const maxDelta = 0.005; // 0.5% tolerance for floating-point / rounding differences

samples.forEach((item, index) => {
  const url = item.url;
  const actualLabel = item.actual_label === 1 ? 'PHISH' : 'SAFE ';
  const pyProb = item.python_probability;

  // Extract features directly in JS from the raw URL
  const featDict = extractFeatures(url);

  // Convert to feature dictionary matching Python schema
  const normalizedFeats = {
    urlLength: featDict.urlLength,
    hostnameLength: featDict.hostnameLength,
    dotCount: featDict.dotCount,
    subdomainCount: featDict.subdomainCount,
    hyphenCount: featDict.hyphenCount,
    hasAtSymbol: featDict.hasAtSymbol ? 1 : 0,
    isIpAddress: featDict.isIpAddress ? 1 : 0,
    digitRatio: featDict.digitRatio,
    specialCharCount: featDict.specialCharCount,
    hasPunycodeOrNonAscii: featDict.hasPunycodeOrNonAscii ? 1 : 0,
    isHttps: featDict.isHttps ? 1 : 0,
    suspiciousTld: featDict.suspiciousTld ? 1 : 0,
    brandKeywordsCount: featDict.brandKeywordsFound ? featDict.brandKeywordsFound.length : 0,
    pathDepth: featDict.pathDepth
  };

  const featureVector = buildFeatureVector(model, normalizedFeats);
  const jsProb = predictProbability(model, featureVector);

  const diff = Math.abs(jsProb - pyProb);
  const isMatch = diff <= maxDelta;

  if (!isMatch) {
    allMatched = false;
  }

  const numStr = String(index + 1).padStart(2, ' ');
  const pyStr = pyProb.toFixed(4).padStart(7, ' ');
  const jsStr = jsProb.toFixed(4).padStart(7, ' ');
  const diffStr = diff.toFixed(4).padStart(6, ' ');
  const matchStr = isMatch ? ' PASS ' : '!FAIL!';
  const displayUrl = url.length > 50 ? url.substring(0, 47) + '...' : url;

  console.log(
    `${numStr} | ${actualLabel}  | ${pyStr} | ${jsStr} | ${diffStr} | ${matchStr} | ${displayUrl}`
  );
});

console.log('----------------------------------------------------------------------------------------------------------\n');

assert.strictEqual(allMatched, true, 'One or more predictions deviated beyond acceptable tolerance.');
console.log('[OK] 20/20 Sample URLs verified: JS in-browser engine matches Python scikit-learn predictions.\n');
