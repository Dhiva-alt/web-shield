/**
 * WebShield - Content Script
 *
 * Privacy & Security Guarantees:
 * - 100% Local DOM inspection.
 * - CRITICAL: NEVER reads, captures, listens to, or stores values typed into ANY
 *   input field or password field (Project Rules 2 & 6).
 * - Only inspects structural DOM attributes: element presence, form action targets,
 *   iframe visibility/nesting, and subresource URLs.
 * - Communicates strictly with the local extension background worker via chrome.runtime.
 */

(function () {
  'use strict';

  // Strictly ignore every document whose scheme is not http: or https:
  if (window.location.protocol !== 'http:' && window.location.protocol !== 'https:') {
    return;
  }

  /**
   * Extracts the registrable domain (eTLD+1) for comparing form actions.
   * Handles common multi-part suffixes like .co.uk, .com.br.
   */
  function getRegistrableDomain(hostname) {
    if (!hostname) return '';
    const cleanHost = hostname.toLowerCase().trim();

    // Raw IPv4/IPv6 address or localhost
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

  /**
   * Scans the document for DOM-level security anomalies.
   */
  function scanDOM() {
    const findings = [];
    const isHttps = window.location.protocol === 'https:';
    const isHttp = window.location.protocol === 'http:';
    const isIframe = window !== window.top;

    // Determine iframe nesting characteristics (hidden or cross-origin)
    let isCrossOriginIframe = false;
    let isHiddenIframeContext = false;

    if (isIframe) {
      try {
        if (window.top.location.origin !== window.location.origin) {
          isCrossOriginIframe = true;
        }
      } catch {
        // Accessing cross-origin window.top throws a SecurityError
        isCrossOriginIframe = true;
      }

      if (window.innerWidth <= 1 || window.innerHeight <= 1) {
        isHiddenIframeContext = true;
      }

      try {
        if (window.frameElement) {
          const frameStyle = window.getComputedStyle(window.frameElement);
          if (
            frameStyle.display === 'none' ||
            frameStyle.visibility === 'hidden' ||
            parseFloat(frameStyle.opacity) === 0
          ) {
            isHiddenIframeContext = true;
          }
        }
      } catch {
        // Cross-origin frameElement access is restricted
      }
    }

    // -------------------------------------------------------------------------
    // 1. Password Input & Form Submission Inspection
    // NOTE: We inspect ONLY the element tag and attributes. We NEVER read .value!
    // -------------------------------------------------------------------------
    const passwordInputs = document.querySelectorAll('input[type="password"]');

    if (passwordInputs.length > 0) {
      // Flag: Password field on unencrypted HTTP page (except localhost and 127.0.0.1)
      const host = (window.location.hostname || '').toLowerCase();
      const isLocalhost = host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
      if (isHttp && !isLocalhost) {
        findings.push('Password input detected on an unencrypted HTTP page (credential exposure risk)');
      }

      // Flag: Password input inside hidden or cross-origin iframe
      if (isIframe && (isCrossOriginIframe || isHiddenIframeContext)) {
        const frameDescriptor = [
          isHiddenIframeContext ? 'hidden' : '',
          isCrossOriginIframe ? 'cross-origin' : ''
        ].filter(Boolean).join('/');
        findings.push(`Password input embedded inside a ${frameDescriptor} iframe (potential phishing overlay)`);
      }

      // Flag: Form submitting to a different registrable domain
      for (const input of passwordInputs) {
        const form = input.closest('form');
        if (form) {
          const rawAction = form.getAttribute('action');
          if (rawAction && !rawAction.startsWith('javascript:') && !rawAction.startsWith('#')) {
            try {
              const targetUrl = new URL(form.action, window.location.href);
              const currentDomain = getRegistrableDomain(window.location.hostname);
              const targetDomain = getRegistrableDomain(targetUrl.hostname);

              if (currentDomain && targetDomain && currentDomain !== targetDomain) {
                findings.push(
                  `Password form action submits to a different domain (${targetUrl.hostname}) than current page (${window.location.hostname})`
                );
              }
            } catch {
              // Ignore unparseable actions
            }
          }
        }
      }
    }

    // -------------------------------------------------------------------------
    // 2. Hidden Iframes Inspection (Top-level & Child Frames)
    // -------------------------------------------------------------------------
    const iframes = document.querySelectorAll('iframe');
    for (const iframe of iframes) {
      let isHidden = false;

      // Check inline styles and attributes
      if (
        iframe.hidden ||
        iframe.getAttribute('width') === '0' ||
        iframe.getAttribute('height') === '0' ||
        iframe.style.display === 'none' ||
        iframe.style.visibility === 'hidden' ||
        iframe.style.opacity === '0'
      ) {
        isHidden = true;
      }

      // Check computed styles
      try {
        const style = window.getComputedStyle(iframe);
        if (
          style.display === 'none' ||
          style.visibility === 'hidden' ||
          parseFloat(style.opacity) === 0 ||
          style.width === '0px' ||
          style.height === '0px'
        ) {
          isHidden = true;
        }
      } catch {
        // Fallback to attribute checks if computed style fails
      }

      if (isHidden) {
        const src = iframe.getAttribute('src') || 'about:blank';
        findings.push(`Hidden iframe detected on page (src: "${src}")`);
      }
    }

    // -------------------------------------------------------------------------
    // 3. Mixed Content Inspection (HTTP Resources on an HTTPS Page)
    // -------------------------------------------------------------------------
    if (isHttps) {
      const activeSelectors = [
        'script[src^="http:"]',
        'link[rel="stylesheet"][href^="http:"]',
        'iframe[src^="http:"]'
      ];
      const passiveSelectors = [
        'img[src^="http:"]',
        'video[src^="http:"]',
        'audio[src^="http:"]',
        'source[src^="http:"]'
      ];

      const activeMixed = document.querySelectorAll(activeSelectors.join(', '));
      const passiveMixed = document.querySelectorAll(passiveSelectors.join(', '));

      if (activeMixed.length > 0) {
        findings.push(`Active mixed content detected: ${activeMixed.length} insecure script/stylesheet/iframe resource(s) on HTTPS page`);
      }
      if (passiveMixed.length > 0) {
        findings.push(`Passive mixed content detected: ${passiveMixed.length} unencrypted image/media resource(s) on HTTPS page`);
      }
    }

    // Deduplicate findings
    const uniqueFindings = [...new Set(findings)];

    if (uniqueFindings.length > 0) {
      chrome.runtime.sendMessage({
        type: 'DOM_FINDINGS',
        url: window.location.href,
        hostname: window.location.hostname,
        isIframe,
        findings: uniqueFindings,
        timestamp: new Date().toISOString()
      }).catch(() => {
        // Service worker may be sleeping; silently handle runtime disconnect
      });
    }
  }

  // Execute scan when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scanDOM);
  } else {
    scanDOM();
  }
})();
