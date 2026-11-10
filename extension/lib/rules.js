/**
 * WebShield - Rule-Based Scoring Engine
 *
 * Evaluates extracted URL features against defensive heuristic weights.
 * Produces:
 * - A normalized risk score from 0.0 (safe) to 1.0 (high risk).
 * - A categorical verdict (SAFE, SUSPICIOUS, HIGH_RISK).
 * - A list of human-readable explanation reasons.
 */

(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.WebShieldRules = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  /**
   * Evaluates feature object and generates a risk score with explanatory reasons.
   * @param {object} features - Feature dictionary produced by WebShieldFeatures.extractFeatures.
   * @returns {{ score: number, verdict: string, reasons: string[] }}
   */
  function evaluateRules(features) {
    if (!features || !features.isValidUrl) {
      return {
        score: 0.85,
        verdict: 'HIGH_RISK',
        reasons: ['Malformed or invalid URL structure']
      };
    }

    let rawScore = 0.0;
    const reasons = [];

    // 1. IP address as host (+0.45)
    if (features.isIpAddress) {
      rawScore += 0.45;
      reasons.push('Uses a raw IP address instead of a registered domain name');
    }

    // 2. Punycode or non-ASCII characters in host (+0.40)
    if (features.hasPunycodeOrNonAscii) {
      rawScore += 0.40;
      reasons.push('Host contains Punycode (xn--) or non-ASCII characters (homograph risk)');
    }

    // 3. '@' symbol present (+0.35)
    if (features.hasAtSymbol) {
      rawScore += 0.35;
      reasons.push("Contains '@' symbol, which can mask the true destination authority");
    }

    // 4. Sensitive brand keywords in subdomain or path/query (+0.35)
    if (features.brandKeywordsFound && features.brandKeywordsFound.length > 0) {
      const keywordList = features.brandKeywordsFound.join(', ');
      rawScore += 0.35;
      reasons.push(`Contains sensitive brand/security keyword(s) (${keywordList}) outside root domain`);
    }

    // 5. Suspicious TLD (+0.30)
    if (features.suspiciousTld) {
      rawScore += 0.30;
      reasons.push(`Uses a frequently abused top-level domain (${features.suspiciousTld})`);
    }

    // 6. Excessive subdomains (+0.20 for >= 3 subdomains, +0.10 for 2)
    if (features.subdomainCount >= 3) {
      rawScore += 0.20;
      reasons.push(`Excessive subdomain nesting (${features.subdomainCount} subdomains)`);
    } else if (features.subdomainCount === 2) {
      rawScore += 0.10;
      reasons.push(`Multiple subdomains (${features.subdomainCount}) detected`);
    }

    // 7. Abnormal URL length (> 120: +0.20, > 80: +0.10)
    if (features.urlLength > 120) {
      rawScore += 0.20;
      reasons.push(`Abnormally long URL (${features.urlLength} characters)`);
    } else if (features.urlLength > 80) {
      rawScore += 0.10;
      reasons.push(`Moderately long URL (${features.urlLength} characters)`);
    }

    // 8. Insecure HTTP connection (+0.15)
    // Treat localhost and 127.0.0.1 as secure per W3C Secure Contexts: no "insecure HTTP" finding
    const host = (features.hostname || '').toLowerCase();
    const isLocalhost = host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
    if (!features.isHttps && !isLocalhost) {
      rawScore += 0.15;
      reasons.push('Insecure connection (HTTP instead of HTTPS)');
    }

    // 9. High digit ratio (> 20%: +0.15, > 10%: +0.08)
    if (features.digitRatio >= 0.20) {
      rawScore += 0.15;
      reasons.push(`High proportion of numeric digits (${(features.digitRatio * 100).toFixed(1)}%) in URL`);
    } else if (features.digitRatio >= 0.10) {
      rawScore += 0.08;
      reasons.push(`Elevated numeric character ratio (${(features.digitRatio * 100).toFixed(1)}%)`);
    }

    // 10. Multiple hyphens in URL (>= 3: +0.15)
    if (features.hyphenCount >= 3) {
      rawScore += 0.15;
      reasons.push(`Excessive hyphens (${features.hyphenCount}) frequently seen in deceptive domains`);
    }

    // 11. Deep path nesting (>= 4: +0.10)
    if (features.pathDepth >= 4) {
      rawScore += 0.10;
      reasons.push(`Deep path nesting (${features.pathDepth} levels)`);
    }

    // Normalize and clamp score between 0.0 and 1.0
    const normalizedScore = Number(Math.min(1.0, Math.max(0.0, rawScore)).toFixed(2));

    let verdict = 'SAFE';
    if (normalizedScore >= 0.70) {
      verdict = 'HIGH_RISK';
    } else if (normalizedScore >= 0.35) {
      verdict = 'SUSPICIOUS';
    }

    return {
      score: normalizedScore,
      verdict,
      reasons
    };
  }

  return {
    evaluateRules
  };
});
