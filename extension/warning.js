/**
 * WebShield - Warning Page Controller
 *
 * Handles:
 * - Query parameter parsing for blocked URL context.
 * - Go Back navigation.
 * - Proceed Anyway bypass logic.
 * - Add to Allowlist action.
 */

/**
 * Retrieves the latest decision record for a target URL from the audit log.
 * Shared source of truth between popup.js and warning.js.
 */
function getLatestWarningRecord(auditLog, targetUrl) {
  if (!Array.isArray(auditLog) || auditLog.length === 0) return null;
  const reversed = auditLog.slice().reverse();
  if (!targetUrl) return reversed[0] || null;

  return reversed.find(item => item.url === targetUrl) ||
         reversed.find(item => item.url && item.url.replace(/\/$/, '') === targetUrl.replace(/\/$/, '')) ||
         reversed[0] ||
         null;
}

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', async () => {
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url') || '';

    const blockedUrlEl = document.getElementById('blocked-url');
    const scoreBadgeEl = document.getElementById('risk-score-badge');
    const mitreBadgeEl = document.getElementById('mitre-badge');
    const reasonsListEl = document.getElementById('reasons-list');
    const btnBack = document.getElementById('btn-back');
    const btnProceed = document.getElementById('btn-proceed');
    const btnAllowlist = document.getElementById('btn-allowlist');

    blockedUrlEl.textContent = targetUrl || 'Unknown URL';

    let targetHostname = '';
    try {
      targetHostname = new URL(targetUrl).hostname;
    } catch {
      targetHostname = targetUrl;
    }

    // Load and render latest audit record for this URL from local storage
    async function loadAndRenderRecord() {
      try {
        const data = await chrome.storage.local.get({ auditLog: [] });
        const log = Array.isArray(data.auditLog) ? data.auditLog : [];
        const matchingRecord = getLatestWarningRecord(log, targetUrl);

        if (matchingRecord) {
          const scorePct = Math.round((matchingRecord.score || 0) * 100);
          const tierStr = matchingRecord.tier || 'HIGH';
          scoreBadgeEl.textContent = `Score: ${scorePct}% (${tierStr} RISK)`;

          const mitreVal = matchingRecord.mitreTechnique || matchingRecord.mitre;
          if (mitreVal) {
            mitreBadgeEl.style.display = 'inline-block';
            mitreBadgeEl.textContent = `MITRE: ${mitreVal}`;
          } else {
            mitreBadgeEl.style.display = 'none';
            mitreBadgeEl.textContent = '';
          }

          // Remove the hardcoded placeholder and render all findings
          reasonsListEl.innerHTML = '';
          if (Array.isArray(matchingRecord.reasons) && matchingRecord.reasons.length > 0) {
            matchingRecord.reasons.forEach(reason => {
              const li = document.createElement('li');
              li.textContent = reason;
              reasonsListEl.appendChild(li);
            });
          } else {
            const li = document.createElement('li');
            li.textContent = 'High risk indicators detected on this destination.';
            reasonsListEl.appendChild(li);
          }
        }
      } catch (err) {
        console.error('[WebShield Warning] Error loading audit details:', err);
      }
    }

    await loadAndRenderRecord();

    // Re-render when storage auditLog changes
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName === 'local' && changes.auditLog) {
          loadAndRenderRecord();
        }
      });
    }

  // 1. Go Back Button (Recommended)
  btnBack.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  // 2. Proceed Anyway Button
  btnProceed.addEventListener('click', async () => {
    if (!targetUrl) return;

    btnProceed.disabled = true;
    btnProceed.textContent = 'Bypassing protection...';

    // Send temporary session bypass token to background worker
    try {
      await chrome.runtime.sendMessage({
        type: 'ALLOW_ONCE_BYPASS',
        url: targetUrl
      });
      window.location.href = targetUrl;
    } catch {
      window.location.href = targetUrl;
    }
  });

  // 3. Add to Allowlist Button
  btnAllowlist.addEventListener('click', async () => {
    if (!targetHostname) return;

    btnAllowlist.disabled = true;
    btnAllowlist.textContent = 'Added to Allowlist!';

    try {
      await chrome.runtime.sendMessage({
        type: 'ADD_ALLOWLIST',
        domain: targetHostname
      });

      // Also allow current bypass and proceed
      await chrome.runtime.sendMessage({
        type: 'ALLOW_ONCE_BYPASS',
        url: targetUrl
      });

      setTimeout(() => {
        window.location.href = targetUrl;
      }, 300);
    } catch (err) {
      console.error('[WebShield Warning] Error adding to allowlist:', err);
      window.location.href = targetUrl;
    }
  });
});
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { getLatestWarningRecord };
}

