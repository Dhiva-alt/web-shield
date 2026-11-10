/**
 * WebShield - Unified Background Service Worker
 *
 * Core Responsibilities:
 * 1. Synchronously evaluates incoming navigations with:
 *    - Heuristic rules (rules.js)
 *    - Local Random Forest ML model (model.js + rf_model.json)
 *    - Security header findings (headers.js)
 *    - In-page DOM / credential findings (content.js)
 * 2. Enforces tiered actions:
 *    - LOW: Log to audit record only.
 *    - MEDIUM: Set warning badge & emit notification.
 *    - HIGH: Redirect immediately to local warning.html.
 * 3. Enforces user allowlist & temporary proceed bypasses.
 * 4. Maintains FIFO audit log capped strictly at 500 entries.
 * 5. Stateless: all persistent state resides in chrome.storage.local.
 */

try {
  importScripts(
    'lib/config.js',
    'lib/features.js',
    'lib/rules.js',
    'lib/headers.js',
    'lib/model.js',
    'lib/risk_engine.js'
  );
} catch (err) {
  console.error('[WebShield] Failed to import script dependencies in service worker:', err);
}

// Storage keys
const AUDIT_LOG_KEY = 'auditLog';
const ALLOWLIST_KEY = 'allowlist';
const BYPASSES_KEY = 'tempBypasses';
const HEADER_FINDINGS_KEY = 'headerFindings';
const DOM_FINDINGS_KEY = 'domFindings';
const CONFIG_OVERRIDE_KEY = 'customConfig';
const MAX_AUDIT_LOG = 500;
const AUDIT_DEDUPE_WINDOW_MS = 5000;

// Track recent evaluations per tab to avoid double-scoring between onBeforeNavigate and onCommitted
const recentEvaluations = new Map();

// In-memory cache of recent audit decisions to prevent race conditions during concurrent events
const recentAuditCache = [];

// Cached in-memory model representation for instant navigation checks
let cachedModel = null;

async function getOrLoadModel() {
  if (cachedModel) return cachedModel;
  try {
    const url = chrome.runtime.getURL('model/rf_model.json');
    const resp = await fetch(url);
    cachedModel = await resp.json();
    return cachedModel;
  } catch (err) {
    console.error('[WebShield] Failed to load rf_model.json:', err);
    return null;
  }
}

/**
 * Validates that a URL strictly belongs to the http: or https: scheme.
 * Non-web schemes (chrome://, devtools://, file:, about:, etc.) must be ignored.
 */
function isHttpOrHttps(url) {
  if (typeof url !== 'string' || !url.trim()) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Appends a decision record to the audit log in chrome.storage.local (capped at 500),
 * deduplicating entries on URL + tier + score + reasons within a 5-second window.
 */
async function recordAuditEntry(entry) {
  if (!entry || !entry.url || !isHttpOrHttps(entry.url)) {
    return;
  }

  // 1. Check in-memory recent cache to prevent race conditions on concurrent events
  if (typeof WebShieldRiskEngine !== 'undefined' && WebShieldRiskEngine.isDuplicateAlert) {
    if (WebShieldRiskEngine.isDuplicateAlert(entry, recentAuditCache, AUDIT_DEDUPE_WINDOW_MS)) {
      return;
    }
  }

  // Record into in-memory cache and prune entries older than 10 seconds
  recentAuditCache.push(entry);
  const now = Date.now();
  while (recentAuditCache.length > 0) {
    const headTime = new Date(recentAuditCache[0].timestamp).getTime();
    if (now - headTime > 10000) {
      recentAuditCache.shift();
    } else {
      break;
    }
  }

  try {
    const data = await chrome.storage.local.get({ [AUDIT_LOG_KEY]: [] });
    const log = Array.isArray(data[AUDIT_LOG_KEY]) ? data[AUDIT_LOG_KEY] : [];

    // 2. Check storage log to deduplicate against persisted records
    if (typeof WebShieldRiskEngine !== 'undefined' && WebShieldRiskEngine.isDuplicateAlert) {
      if (WebShieldRiskEngine.isDuplicateAlert(entry, log, AUDIT_DEDUPE_WINDOW_MS)) {
        return;
      }
    }

    log.push(entry);
    const trimmed = log.slice(-MAX_AUDIT_LOG);

    await chrome.storage.local.set({ [AUDIT_LOG_KEY]: trimmed });
  } catch (err) {
    console.error('[WebShield] Error writing audit log:', err);
  }
}

/**
 * Main evaluation pipeline for a navigation event.
 */
async function processNavigation(tabId, rawUrl) {
  // Strictly ignore every URL whose scheme is not http or https
  if (!rawUrl || !isHttpOrHttps(rawUrl)) return;

  // Record this navigation immediately to prevent double-scoring on late commit
  recentEvaluations.set(tabId, { url: rawUrl, time: Date.now() });

  try {
    const storageData = await chrome.storage.local.get({
      [ALLOWLIST_KEY]: [],
      [BYPASSES_KEY]: {},
      [HEADER_FINDINGS_KEY]: {},
      [DOM_FINDINGS_KEY]: {},
      [CONFIG_OVERRIDE_KEY]: null
    });

    const allowlist = storageData[ALLOWLIST_KEY] || [];
    const bypasses = storageData[BYPASSES_KEY] || {};
    const headerFindingsStore = storageData[HEADER_FINDINGS_KEY] || {};
    const domFindingsStore = storageData[DOM_FINDINGS_KEY] || {};
    const customConfig = storageData[CONFIG_OVERRIDE_KEY];

    // Check if user clicked "Proceed anyway" for this URL
    if (bypasses[rawUrl]) {
      const bypassTime = bypasses[rawUrl];
      // Valid for 10 minutes
      if (Date.now() - bypassTime < 600000) {
        console.log(`[WebShield] User bypass active for ${rawUrl}. Skipping block.`);
        chrome.action.setBadgeText({ text: 'BYPASS', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#64748b', tabId });
        return;
      } else {
        delete bypasses[rawUrl];
        await chrome.storage.local.set({ [BYPASSES_KEY]: bypasses });
      }
    }

    // 1. Extract lexical features
    const features = WebShieldFeatures.extractFeatures(rawUrl);

    // 2. Evaluate heuristic rules
    const ruleResult = WebShieldRules.evaluateRules(features);

    // 3. Evaluate offline Random Forest model
    let mlProbability = 0.0;
    const model = await getOrLoadModel();
    if (model) {
      const vector = WebShieldModel.buildFeatureVector(model, {
        urlLength: features.urlLength,
        hostnameLength: features.hostnameLength,
        dotCount: features.dotCount,
        subdomainCount: features.subdomainCount,
        hyphenCount: features.hyphenCount,
        hasAtSymbol: features.hasAtSymbol ? 1 : 0,
        isIpAddress: features.isIpAddress ? 1 : 0,
        digitRatio: features.digitRatio,
        specialCharCount: features.specialCharCount,
        hasPunycodeOrNonAscii: features.hasPunycodeOrNonAscii ? 1 : 0,
        isHttps: features.isHttps ? 1 : 0,
        suspiciousTld: features.suspiciousTld ? 1 : 0,
        brandKeywordsCount: features.brandKeywordsFound ? features.brandKeywordsFound.length : 0,
        pathDepth: features.pathDepth
      });
      mlProbability = WebShieldModel.predictProbability(model, vector);
    }

    // 4. Retrieve existing header and DOM findings for this host/URL
    let hostname = '';
    try {
      hostname = new URL(rawUrl).hostname;
    } catch {
      hostname = rawUrl;
    }

    const hostHeaderData = headerFindingsStore[hostname] || {};
    const headerFindings = hostHeaderData.findings || [];

    const urlDomData = domFindingsStore[rawUrl] || {};
    const domFindings = urlDomData.findings || [];

    // 5. Compute Unified Risk Assessment
    const risk = WebShieldRiskEngine.evaluateRisk({
      url: rawUrl,
      ruleScore: ruleResult.score,
      ruleReasons: ruleResult.reasons,
      mlProbability,
      headerFindings,
      domFindings,
      allowlist,
      customThresholds: customConfig ? customConfig.thresholds : null
    });

    // 6. Record in Audit Log
    const decisionRecord = {
      timestamp: new Date().toISOString(),
      url: rawUrl,
      score: risk.score,
      tier: risk.tier,
      reasons: risk.reasons,
      mitre: risk.mitreTechnique || null,
      mitreTechnique: risk.mitreTechnique || null,
      signals: risk.signals
    };
    await recordAuditEntry(decisionRecord);

    console.log(
      `[WebShield Decision] Tier: ${risk.tier} | Score: ${risk.score} | URL: ${rawUrl} | MITRE: ${risk.mitreTechnique}`
    );

    // 7. Enforce Tier Action
    if (risk.tier === 'HIGH') {
      // Set High Risk badge
      chrome.action.setBadgeText({ text: '!', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId });

      // Redirect to warning page
      const warningUrl = chrome.runtime.getURL(
        `warning.html?url=${encodeURIComponent(rawUrl)}`
      );
      chrome.tabs.update(tabId, { url: warningUrl });
    } else if (risk.tier === 'MEDIUM') {
      // Set Warning badge
      chrome.action.setBadgeText({ text: 'WARN', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId });

      // Dispatch desktop notification safely wrapped in try/catch
      try {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: chrome.runtime.getURL('icons/icon48.png'),
          title: 'WebShield Warning: Suspicious Site',
          message: `Caution: ${hostname} flagged as medium risk (${(risk.score * 100).toFixed(0)}%).` +
                   (risk.mitreTechnique ? ` MITRE: ${risk.mitreTechnique}` : ''),
          priority: 1
        }, (notificationId) => {
          if (chrome.runtime.lastError) {
            console.warn('[WebShield] Notification warning:', chrome.runtime.lastError.message);
          }
        });
      } catch (notifyErr) {
        console.error('[WebShield] Failed to create notification:', notifyErr);
      }
    } else if (risk.tier === 'ALLOWLISTED') {
      chrome.action.setBadgeText({ text: 'OK', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#10b981', tabId });
    } else {
      // LOW: Log only
      chrome.action.setBadgeText({ text: '', tabId });
    }
  } catch (err) {
    console.error('[WebShield] Error processing navigation decision:', err);
  }
}

// ---------------------------------------------------------------------------
// 1. Navigation Start Listener (Scores URLs on navigation start before headers/load)
// ---------------------------------------------------------------------------
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0) {
    processNavigation(details.tabId, details.url);
  }
});

// Fallback commit listener (catches redirects/late commits without double-scoring)
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    const last = recentEvaluations.get(details.tabId);
    if (!last || last.url !== details.url || (Date.now() - last.time > 3000)) {
      processNavigation(details.tabId, details.url);
    }
  }
});

// ---------------------------------------------------------------------------
// 2. Read-Only Security Headers Inspector
// ---------------------------------------------------------------------------
chrome.webRequest.onHeadersReceived.addListener(
  async (details) => {
    if (details.type !== 'main_frame' || !details.responseHeaders || !isHttpOrHttps(details.url)) return;

    const inspection = WebShieldHeaders.inspectResponseHeaders(details.responseHeaders, details.url);
    if (!inspection || inspection.findings.length === 0) return;

    try {
      const data = await chrome.storage.local.get({ [HEADER_FINDINGS_KEY]: {} });
      const store = data[HEADER_FINDINGS_KEY] || {};

      store[inspection.hostname] = {
        hostname: inspection.hostname,
        origin: inspection.url,
        lastSeen: new Date().toISOString(),
        severity: inspection.severity,
        findings: inspection.findings
      };

      await chrome.storage.local.set({ [HEADER_FINDINGS_KEY]: store });
    } catch (err) {
      console.error('[WebShield] Error recording header findings:', err);
    }
  },
  { urls: ['<all_urls>'], types: ['main_frame'] },
  ['responseHeaders']
);

// ---------------------------------------------------------------------------
// 3. Runtime Message Handlers (Allowlist, Bypasses, Content Script DOM Findings)
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return;

  (async () => {
    try {
      // A. Content Script DOM Findings
      if (message.type === 'DOM_FINDINGS') {
        const data = await chrome.storage.local.get({ [DOM_FINDINGS_KEY]: {} });
        const store = data[DOM_FINDINGS_KEY] || {};

        store[message.url] = {
          url: message.url,
          hostname: message.hostname,
          isIframe: Boolean(message.isIframe),
          lastSeen: message.timestamp || new Date().toISOString(),
          findings: message.findings
        };

        await chrome.storage.local.set({ [DOM_FINDINGS_KEY]: store });

        // If high risk DOM findings (e.g. cross-domain password submission), re-evaluate tab!
        if (sender && sender.tab && sender.tab.id) {
          processNavigation(sender.tab.id, message.url);
        }

        sendResponse({ status: 'ok' });
        return;
      }

      // B. Proceed Anyway: Temporary 10-Minute Session Bypass
      if (message.type === 'ALLOW_ONCE_BYPASS') {
        const data = await chrome.storage.local.get({ [BYPASSES_KEY]: {} });
        const bypasses = data[BYPASSES_KEY] || {};
        bypasses[message.url] = Date.now();
        await chrome.storage.local.set({ [BYPASSES_KEY]: bypasses });
        sendResponse({ status: 'ok', url: message.url });
        return;
      }

      // C. Allowlist Management: Add Domain
      if (message.type === 'ADD_ALLOWLIST') {
        const domain = (message.domain || '').toLowerCase().trim();
        if (domain) {
          const data = await chrome.storage.local.get({ [ALLOWLIST_KEY]: [] });
          const list = Array.isArray(data[ALLOWLIST_KEY]) ? data[ALLOWLIST_KEY] : [];
          if (!list.includes(domain)) {
            list.push(domain);
            await chrome.storage.local.set({ [ALLOWLIST_KEY]: list });
          }
        }
        sendResponse({ status: 'ok', domain });
        return;
      }

      // D. Allowlist Management: Remove Domain
      if (message.type === 'REMOVE_ALLOWLIST') {
        const domain = (message.domain || '').toLowerCase().trim();
        const data = await chrome.storage.local.get({ [ALLOWLIST_KEY]: [] });
        const list = (data[ALLOWLIST_KEY] || []).filter(d => d !== domain);
        await chrome.storage.local.set({ [ALLOWLIST_KEY]: list });
        sendResponse({ status: 'ok', domain });
        return;
      }

      // E. Allowlist Management: Get Allowlist
      if (message.type === 'GET_ALLOWLIST') {
        const data = await chrome.storage.local.get({ [ALLOWLIST_KEY]: [] });
        sendResponse({ allowlist: data[ALLOWLIST_KEY] || [] });
        return;
      }
    } catch (err) {
      console.error('[WebShield] Message handling error:', err);
      sendResponse({ status: 'error', error: err.message });
    }
  })();

  return true; // Keep message channel open for async response
});

// ---------------------------------------------------------------------------
// 4. Service Worker Lifecycle Initialization
// ---------------------------------------------------------------------------
chrome.runtime.onInstalled.addListener(async () => {
  try {
    const existing = await chrome.storage.local.get([
      AUDIT_LOG_KEY,
      ALLOWLIST_KEY,
      BYPASSES_KEY,
      HEADER_FINDINGS_KEY,
      DOM_FINDINGS_KEY
    ]);
    const init = {};
    if (!existing[AUDIT_LOG_KEY]) init[AUDIT_LOG_KEY] = [];
    if (!existing[ALLOWLIST_KEY]) init[ALLOWLIST_KEY] = [];
    if (!existing[BYPASSES_KEY]) init[BYPASSES_KEY] = {};
    if (!existing[HEADER_FINDINGS_KEY]) init[HEADER_FINDINGS_KEY] = {};
    if (!existing[DOM_FINDINGS_KEY]) init[DOM_FINDINGS_KEY] = {};

    if (Object.keys(init).length > 0) {
      await chrome.storage.local.set(init);
    }
    console.log('[WebShield] Service worker initialized. Unified risk engine ready.');
  } catch (err) {
    console.error('[WebShield] Initialization error:', err);
  }
});
