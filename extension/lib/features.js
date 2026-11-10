/**
 * WebShield - URL Feature Extractor
 *
 * Privacy & Security Guarantees:
 * - 100% Local processing: runs synchronously on URL strings only.
 * - Never touches or accesses DOM content, form inputs, or credentials.
 * - Usable in both browser extensions (MV3 service workers/popups) and Node.js.
 */

(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.WebShieldFeatures = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Recognized suspicious / disproportionately abused TLDs
  const SUSPICIOUS_TLDS = new Set([
    'tk', 'xyz', 'top', 'click', 'gq', 'ml', 'cf', 'ga',
    'buzz', 'fit', 'rest', 'work', 'download', 'surf', 'loan'
  ]);

  // Frequently targeted brand and authentication keywords
  const BRAND_KEYWORDS = [
    'paypal',
    'google',
    'microsoft',
    'bank',
    'login',
    'verify',
    'secure'
  ];

  // Regex patterns
  const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
  const IPV6_REGEX = /^(?:\[)?[0-9a-fA-F:]+(?:\])?$/;
  const SPECIAL_CHARS_REGEX = /[-_.~!*'();:@&=+$,/?%#[\]]/g;

  /**
   * Safely parses a URL string, adding a fallback scheme if omitted.
   * @param {string} urlStr
   * @returns {URL|null}
   */
  function parseUrl(urlStr) {
    if (typeof urlStr !== 'string') return null;
    const trimmed = urlStr.trim();
    if (!trimmed) return null;

    try {
      return new URL(trimmed);
    } catch {
      // If missing protocol, attempt to parse with http:// fallback
      try {
        return new URL('http://' + trimmed);
      } catch {
        return null;
      }
    }
  }

  /**
   * Extracts lexical, structural, and heuristic features from a given URL.
   * @param {string} urlStr - The URL to inspect.
   * @returns {object} Extracted feature dictionary.
   */
  function extractFeatures(urlStr) {
    const parsed = parseUrl(urlStr);
    const rawUrl = (urlStr || '').trim();

    if (!parsed) {
      return {
        urlLength: rawUrl.length,
        hostnameLength: 0,
        dotCount: (rawUrl.match(/\./g) || []).length,
        subdomainCount: 0,
        hyphenCount: (rawUrl.match(/-/g) || []).length,
        hasAtSymbol: rawUrl.includes('@'),
        isIpAddress: false,
        digitRatio: 0,
        specialCharCount: (rawUrl.match(SPECIAL_CHARS_REGEX) || []).length,
        hasPunycodeOrNonAscii: false,
        isHttps: false,
        suspiciousTld: null,
        brandKeywordsFound: [],
        pathDepth: 0,
        isValidUrl: false
      };
    }

    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname;
    const search = parsed.search;
    const protocol = parsed.protocol;

    // 1. URL and Hostname Lengths
    const urlLength = rawUrl.length;
    const hostnameLength = hostname.length;

    // 2. Dots count across full URL
    const dotCount = (rawUrl.match(/\./g) || []).length;

    // 3. IP address host check
    const isIpAddress = IPV4_REGEX.test(hostname) || (IPV6_REGEX.test(hostname) && hostname.includes(':'));

    // 4. Subdomain calculation
    let subdomainCount = 0;
    let tld = '';
    let mainDomain = '';

    if (!isIpAddress && hostname.includes('.')) {
      const hostParts = hostname.split('.');
      tld = hostParts[hostParts.length - 1];

      // Handle common two-part public suffixes (e.g. .co.uk, .com.br)
      const isTwoPartSuffix = hostParts.length >= 3 &&
        (hostParts[hostParts.length - 2] === 'co' || hostParts[hostParts.length - 2] === 'com');

      const domainPartsCount = isTwoPartSuffix ? 3 : 2;
      if (hostParts.length > domainPartsCount) {
        subdomainCount = hostParts.length - domainPartsCount;
        mainDomain = hostParts[hostParts.length - domainPartsCount];
      } else if (hostParts.length >= 2) {
        mainDomain = hostParts[0];
      }
    }

    // 5. Hyphen count
    const hyphenCount = (rawUrl.match(/-/g) || []).length;

    // 6. @ symbol presence
    const hasAtSymbol = rawUrl.includes('@');

    // 7. Digit ratio (digits / total length)
    const digits = (rawUrl.match(/\d/g) || []).length;
    const digitRatio = urlLength > 0 ? Number((digits / urlLength).toFixed(4)) : 0;

    // 8. Special characters count
    const specialCharMatches = rawUrl.match(SPECIAL_CHARS_REGEX);
    const specialCharCount = specialCharMatches ? specialCharMatches.length : 0;

    // 9. Punycode or non-ASCII in hostname
    const hasPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
    const hasNonAscii = /[^\x00-\x7F]/.test(hostname);
    const hasPunycodeOrNonAscii = hasPunycode || hasNonAscii;

    // 10. HTTPS check
    const isHttps = protocol === 'https:';

    // 11. Suspicious TLD check
    let detectedSuspiciousTld = null;
    if (tld && SUSPICIOUS_TLDS.has(tld)) {
      detectedSuspiciousTld = '.' + tld;
    }

    // 12. Brand keywords search in subdomain or path/query
    // Target brand names appearing in subdomains or path/query,
    // but not when the root domain itself is legitimately that brand.
    const subdomainsString = hostname.split('.').slice(0, subdomainCount).join('.');
    const pathAndQuery = (pathname + search).toLowerCase();
    const brandKeywordsFound = [];

    for (const brand of BRAND_KEYWORDS) {
      const inSubdomain = subdomainsString.includes(brand);
      const inPathOrQuery = pathAndQuery.includes(brand);

      if (inSubdomain || inPathOrQuery) {
        // Only flag if mainDomain is NOT genuinely that brand
        if (mainDomain !== brand) {
          brandKeywordsFound.push(brand);
        }
      }
    }

    // 13. Path Depth
    const pathSegments = pathname.split('/').filter(segment => segment.length > 0);
    const pathDepth = pathSegments.length;

    return {
      urlLength,
      hostnameLength,
      dotCount,
      subdomainCount,
      hyphenCount,
      hasAtSymbol,
      isIpAddress,
      digitRatio,
      specialCharCount,
      hasPunycodeOrNonAscii,
      isHttps,
      suspiciousTld: detectedSuspiciousTld,
      brandKeywordsFound,
      pathDepth,
      isValidUrl: true,
      hostname
    };
  }

  return {
    extractFeatures,
    SUSPICIOUS_TLDS,
    BRAND_KEYWORDS
  };
});
