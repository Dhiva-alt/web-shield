/**
 * WebShield - Security Headers Analyzer
 *
 * Privacy & Security Guarantees:
 * - 100% Local processing: read-only inspection of HTTP response headers.
 * - Does not modify, block, or delay network traffic.
 * - Never logs or stores cookie names, values, or session tokens (Project Rule 6).
 * - Flags missing defensive headers as LOW severity configuration hygiene issues.
 */

(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.WebShieldHeaders = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  /**
   * Inspects HTTP response headers for missing defensive security headers
   * and insecure cookie configurations.
   *
   * @param {Array<{name: string, value?: string}>} responseHeaders - Chrome webRequest response headers.
   * @param {string} urlStr - Target main-frame URL.
   * @returns {{ hostname: string, url: string, severity: string, findings: string[], timestamp: string } | null}
   */
  function inspectResponseHeaders(responseHeaders, urlStr) {
    let parsedUrl;
    try {
      parsedUrl = new URL(urlStr);
    } catch {
      return null;
    }

    const hostname = parsedUrl.hostname;
    const isHttps = parsedUrl.protocol === 'https:';
    const headers = responseHeaders || [];

    // Map header names (case-insensitive)
    const headerMap = new Map();
    const cookieHeaders = [];

    for (const h of headers) {
      if (!h || !h.name) continue;
      const name = h.name.toLowerCase();
      if (name === 'set-cookie') {
        cookieHeaders.push(h.value || '');
      } else {
        headerMap.set(name, h.value || '');
      }
    }

    const findings = [];

    // 1. Content-Security-Policy
    if (!headerMap.has('content-security-policy')) {
      findings.push('Missing Content-Security-Policy (CSP) header');
    }

    // 2. Strict-Transport-Security (applicable to HTTPS origins)
    if (isHttps && !headerMap.has('strict-transport-security')) {
      findings.push('Missing Strict-Transport-Security (HSTS) header on HTTPS site');
    }

    // 3. X-Frame-Options (Clickjacking defense, unless covered by CSP frame-ancestors)
    const csp = headerMap.get('content-security-policy') || '';
    const hasFrameAncestors = /frame-ancestors\s+/i.test(csp);
    if (!headerMap.has('x-frame-options') && !hasFrameAncestors) {
      findings.push('Missing X-Frame-Options header (clickjacking protection)');
    }

    // 4. X-Content-Type-Options (MIME sniffing defense)
    const xcto = headerMap.get('x-content-type-options') || '';
    if (!xcto.toLowerCase().includes('nosniff')) {
      findings.push('Missing X-Content-Type-Options: nosniff header');
    }

    // 5. Insecure Cookie Flags (Secure & HttpOnly)
    // IMPORTANT: Per Project Rule 6, we NEVER extract or record cookie names or values.
    let missingSecureCount = 0;
    let missingHttpOnlyCount = 0;

    for (const cookieStr of cookieHeaders) {
      const attributes = cookieStr.split(';').map(attr => attr.trim().toLowerCase());
      const hasSecure = attributes.includes('secure');
      const hasHttpOnly = attributes.includes('httponly');

      if (!hasSecure) missingSecureCount++;
      if (!hasHttpOnly) missingHttpOnlyCount++;
    }

    if (missingHttpOnlyCount > 0) {
      findings.push(`Cookie set without HttpOnly flag (${missingHttpOnlyCount} observed)`);
    }

    if (missingSecureCount > 0) {
      findings.push(`Cookie set without Secure flag (${missingSecureCount} observed)`);
    }

    return {
      hostname,
      url: parsedUrl.origin,
      severity: 'LOW',
      findings,
      timestamp: new Date().toISOString()
    };
  }

  return {
    inspectResponseHeaders
  };
});
