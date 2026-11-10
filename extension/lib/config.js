/**
 * WebShield - Centralized Security & Risk Configuration
 *
 * Configurable thresholds, weights, MITRE ATT&CK technique tags,
 * and storage limits. Stored in one place for easy user tuning.
 */

(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.WebShieldConfig = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const DEFAULT_CONFIG = {
    // Risk tier score cutoffs (0.0 to 1.0)
    thresholds: {
      mediumRisk: 0.40, // Score >= 0.40 triggers MEDIUM (badge + notification)
      highRisk: 0.70    // Score >= 0.70 triggers HIGH (warning page redirect)
    },

    // Relative weights for score combination
    weights: {
      rules: 0.45,   // Heuristic and lexical rule engine
      ml: 0.40,      // Offline Random Forest model probability
      dom: 0.15      // Password and frame structural findings
    },

    // Audit log constraints
    maxAuditEntries: 500,

    // MITRE ATT&CK Technique Mapping (Phishing & Credential Theft only)
    mitreTechniques: {
      phishingLink: 'T1566.002: Spearphishing Link',
      credentialHarvest: 'T1552: Unsecured Credentials',
      clickjacking: 'T1204.001: Malicious Link',
      homograph: 'T1566: Phishing (IDN Homograph)',
      generalPhish: 'T1566: Phishing'
    }
  };

  return DEFAULT_CONFIG;
});
