/**
 * WebShield - Unified Risk Engine
 *
 * Integrates:
 * 1. Lexical & heuristic rules (rules.js)
 * 2. Offline Random Forest ML model probability (model.js)
 * 3. Security header findings (headers.js)
 * 4. In-page DOM / password form findings (content.js)
 * 5. User-managed site allowlist
 *
 * Computes a unified 0-1 risk score, assigns a tier (LOW, MEDIUM, HIGH, ALLOWLISTED),
 * and maps findings to MITRE ATT&CK techniques.
 */

(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    const config = require('./config.js');
    module.exports = factory(config);
  } else {
    root.WebShieldRiskEngine = factory(root.WebShieldConfig);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (config) {
  'use strict';

  const cfg = config || {
    thresholds: { mediumRisk: 0.40, highRisk: 0.70 },
    weights: { rules: 0.45, ml: 0.40, dom: 0.15 },
    mitreTechniques: {
      phishingLink: 'T1566.002: Spearphishing Link',
      credentialHarvest: 'T1552: Unsecured Credentials',
      clickjacking: 'T1204.001: Malicious Link',
      homograph: 'T1566: Phishing (IDN Homograph)',
      generalPhish: 'T1566: Phishing'
    }
  };

  /**
   * Checks whether a hostname or URL is present in the user's allowlist.
   *
   * @param {string} urlStr - Destination URL or hostname.
   * @param {Array<string>} allowlist - Array of user-allowed domains/patterns.
   * @returns {boolean}
   */
  function isAllowlisted(urlStr, allowlist) {
    if (!urlStr || !Array.isArray(allowlist) || allowlist.length === 0) {
      return false;
    }

    let hostname = '';
    try {
      hostname = new URL(urlStr).hostname.toLowerCase();
    } catch {
      hostname = String(urlStr).toLowerCase().trim();
    }

    return allowlist.some((item) => {
      if (!item) return false;
      const cleanItem = item.toLowerCase().trim();
      return (
        hostname === cleanItem ||
        hostname.endsWith('.' + cleanItem) ||
        urlStr.toLowerCase().startsWith(cleanItem)
      );
    });
  }

  /**
   * Validates whether a URL has an http: or https: protocol.
   * Internal browser schemes, file URLs, and other schemes are rejected.
   */
  function isHttpOrHttps(urlStr) {
    if (typeof urlStr !== 'string' || !urlStr.trim()) return false;
    try {
      const parsed = new URL(urlStr);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  }

  /**
   * Resolves the primary MITRE ATT&CK technique for the detected reasons.
   * CRITICAL: Shows a MITRE technique ONLY when a phishing or credential-theft
   * indicator fired. Header and HTTP hygiene findings get NO MITRE tag.
   */
  function resolveMitreTechnique(reasons, domFindings) {
    const list = [...(reasons || []), ...(domFindings || [])];
    if (list.length === 0) return null;

    const joined = list.join(' ').toLowerCase();

    // 1. Credential Harvesting (T1552)
    if (
      joined.includes('submits to a different domain') ||
      joined.includes('embedded inside a hidden iframe') ||
      joined.includes('embedded inside a cross-origin iframe')
    ) {
      return cfg.mitreTechniques.credentialHarvest;
    }

    // 2. IDN Homograph Phishing (T1566)
    if (joined.includes('homograph') || joined.includes('punycode')) {
      return cfg.mitreTechniques.homograph;
    }

    // 3. Clickjacking / Deceptive Frame Overlay (T1204.001)
    if (joined.includes('clickjacking') || joined.includes('hidden iframe')) {
      return cfg.mitreTechniques.clickjacking;
    }

    // 4. Spearphishing Link / Deceptive Authority / Brand Impersonation (T1566.002)
    if (
      joined.includes('brand') ||
      joined.includes('frequently abused top-level domain') ||
      joined.includes('suspicious top-level domain') ||
      joined.includes('raw ip address') ||
      joined.includes("contains '@' symbol") ||
      joined.includes('combosquatting') ||
      joined.includes('excessive subdomain nesting')
    ) {
      return cfg.mitreTechniques.phishingLink;
    }

    // Header and HTTP hygiene findings (CSP, HSTS, XFO, cookies, unencrypted HTTP) get NO MITRE tag.
    return null;
  }

  /**
   * Computes a unified risk evaluation across all detection modules.
   *
   * @param {object} params
   * @param {string} params.url - Evaluated URL.
   * @param {number} params.ruleScore - Heuristic score from rules.js (0.0 to 1.0).
   * @param {Array<string>} params.ruleReasons - Explanations from rules.js.
   * @param {number} params.mlProbability - Random Forest probability from model.js (0.0 to 1.0).
   * @param {Array<string>} [params.headerFindings] - Security header findings.
   * @param {Array<string>} [params.domFindings] - DOM/password form findings.
   * @param {Array<string>} [params.allowlist] - User allowlist.
   * @param {object} [params.customThresholds] - Optional overridden thresholds.
   * @returns {object} Unified risk evaluation.
   */
  function evaluateRisk(params) {
    const {
      url,
      ruleScore = 0.0,
      ruleReasons = [],
      mlProbability = 0.0,
      headerFindings = [],
      domFindings = [],
      allowlist = [],
      customThresholds
    } = params;

    const thresholds = customThresholds || cfg.thresholds;
    const weights = cfg.weights;

    // 0. Strictly ignore non-http and non-https schemes (chrome://, devtools://, file:, about:)
    if (!isHttpOrHttps(url)) {
      return {
        score: 0.0,
        tier: 'IGNORED',
        reasons: ['URL scheme is not http or https; skipped scoring.'],
        mitreTechnique: null,
        isAllowlisted: false,
        signals: {
          ruleScore: 0,
          mlProbability: 0,
          headerCount: 0,
          domCount: 0
        }
      };
    }

    // 1. Check Allowlist
    if (isAllowlisted(url, allowlist)) {
      return {
        score: 0.0,
        tier: 'ALLOWLISTED',
        reasons: ['Site is in user-approved allowlist.'],
        mitreTechnique: 'N/A (Allowlisted)',
        isAllowlisted: true,
        signals: {
          ruleScore,
          mlProbability,
          headerCount: headerFindings.length,
          domCount: domFindings.length
        }
      };
    }

    // 2. DOM Penalty Calculation
    // Critical DOM issues (e.g. cross-domain password submission) immediately escalate risk
    let domPenalty = 0.0;
    let hasCriticalDomOverride = false;
    let overrideReason = null;
    const reasons = [...ruleReasons];

    if (domFindings.length > 0) {
      for (const df of domFindings) {
        reasons.push(`[DOM] ${df}`);
        if (df.includes('submits to a different domain')) {
          domPenalty += 0.50; // Critical credential risk
          hasCriticalDomOverride = true;
          overrideReason = 'Override: Cross-domain password submission detected (forces HIGH risk tier)';
        } else if (df.includes('embedded inside a hidden iframe') || df.includes('embedded inside a cross-origin iframe')) {
          domPenalty += 0.50;
          hasCriticalDomOverride = true;
          overrideReason = 'Override: Password form inside hidden/cross-origin iframe detected (forces HIGH risk tier)';
        } else if (df.includes('unencrypted HTTP')) {
          domPenalty += 0.25;
        } else {
          domPenalty += 0.15;
        }
      }
    }

    // Header Findings note (LOW severity hygiene)
    if (headerFindings.length > 0) {
      for (const hf of headerFindings) {
        reasons.push(`[Header] ${hf}`);
      }
    }

    // 3. Weighted Combination
    const combinedRaw =
      (ruleScore * weights.rules) +
      (mlProbability * weights.ml) +
      (Math.min(1.0, domPenalty) * weights.dom);

    let score = Number(Math.min(1.0, Math.max(0.0, combinedRaw)).toFixed(2));

    // 4. Tier Assignment & Score/Tier Agreement
    // Tier cutoffs:
    //   HIGH: score >= highRisk (0.70) OR critical override rule
    //   MEDIUM: highRisk > score >= mediumRisk (0.40)
    //   LOW: score < mediumRisk
    let tier = 'LOW';
    if (score >= thresholds.highRisk || hasCriticalDomOverride) {
      tier = 'HIGH';
      if (hasCriticalDomOverride) {
        // Enforce strict score/tier agreement: score must reflect HIGH tier (>= highRisk cutoff)
        score = Math.max(score, thresholds.highRisk);
        if (overrideReason) {
          reasons.unshift(overrideReason);
        }
      }
    } else if (score >= thresholds.mediumRisk) {
      tier = 'MEDIUM';
    }

    // 5. MITRE ATT&CK Mapping (Phishing & Credential Theft only; hygiene gets no MITRE tag)
    const mitreTechnique = resolveMitreTechnique(ruleReasons, domFindings);

    return {
      score,
      tier,
      reasons: [...new Set(reasons)],
      mitreTechnique,
      isAllowlisted: false,
      signals: {
        ruleScore,
        mlProbability,
        headerCount: headerFindings.length,
        domCount: domFindings.length
      }
    };
  }

  return {
    isAllowlisted,
    isHttpOrHttps,
    evaluateRisk,
    resolveMitreTechnique,
    DEFAULT_CONFIG: cfg
  };
});
