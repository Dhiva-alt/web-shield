/**
 * WebShield - Warning Page Controller
 *
 * Handles:
 * - Query parameter parsing for blocked URL context.
 * - Go Back navigation.
 * - Proceed Anyway bypass logic.
 * - Add to Allowlist action.
 */

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

  // Load latest audit record for this URL from local storage
  try {
    const data = await chrome.storage.local.get({ auditLog: [] });
    const log = Array.isArray(data.auditLog) ? data.auditLog : [];
    const matchingRecord = log.find(item => item.url === targetUrl) || log[log.length - 1];

    if (matchingRecord) {
      scoreBadgeEl.textContent = `Score: ${(matchingRecord.score * 100).toFixed(0)}% (HIGH RISK)`;
      if (matchingRecord.mitreTechnique) {
        mitreBadgeEl.textContent = `MITRE: ${matchingRecord.mitreTechnique}`;
      }

      if (Array.isArray(matchingRecord.reasons) && matchingRecord.reasons.length > 0) {
        reasonsListEl.innerHTML = '';
        matchingRecord.reasons.forEach(reason => {
          const li = document.createElement('li');
          li.textContent = reason;
          reasonsListEl.appendChild(li);
        });
      }
    }
  } catch (err) {
    console.error('[WebShield Warning] Error loading audit details:', err);
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
