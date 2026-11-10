/**
 * WebShield - Popup UI Controller
 *
 * Responsibilities:
 * 1. Current site assessment: score, tier, and itemized reasons.
 * 2. Allowlist toggle for the active domain.
 * 3. Recent alerts feed: displays the last 10 security decisions.
 * 4. SIEM Export: downloads audit log as JSON Lines (.jsonl) for ingestion
 *    into Wazuh, Splunk, or Elastic.
 *
 * Privacy & Security Guarantees:
 * - 100% Client-side: downloads are triggered locally via Blob object URLs.
 * - Zero external server communication or telemetry.
 */

document.addEventListener('DOMContentLoaded', async () => {
  // UI Elements
  const statusBadge = document.getElementById('status-badge');
  const activeUrlEl = document.getElementById('active-url');
  const riskScoreEl = document.getElementById('risk-score');
  const tierLabelEl = document.getElementById('tier-label');
  const mitreTagEl = document.getElementById('mitre-tag');
  const reasonsListEl = document.getElementById('reasons-list');
  const btnAllowlist = document.getElementById('btn-allowlist');
  const alertsCounter = document.getElementById('alerts-counter');
  const alertsListEl = document.getElementById('alerts-list');
  const btnExport = document.getElementById('btn-export');

  let currentTabUrl = '';
  let currentHostname = '';

  // 1. Query Active Browser Tab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs[0] && tabs[0].url) {
      currentTabUrl = tabs[0].url;
      try {
        currentHostname = new URL(currentTabUrl).hostname.toLowerCase();
      } catch {
        currentHostname = currentTabUrl.toLowerCase();
      }
    }
  } catch (err) {
    console.error('[WebShield Popup] Error fetching active tab:', err);
  }

  activeUrlEl.textContent = currentTabUrl || 'No active web page';

  function isHttpOrHttps(url) {
    if (typeof url !== 'string' || !url.trim()) return false;
    try {
      const parsed = new URL(url);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  }

  // 2. Fetch Storage (Audit Log & Allowlist)
  let auditLog = [];
  let allowlist = [];

  try {
    const storage = await chrome.storage.local.get({
      auditLog: [],
      allowlist: []
    });
    // Filter to ensure no non-http/https entries are ever rendered or exported
    auditLog = (Array.isArray(storage.auditLog) ? storage.auditLog : []).filter(
      entry => isHttpOrHttps(entry.url)
    );
    allowlist = Array.isArray(storage.allowlist) ? storage.allowlist : [];
  } catch (err) {
    console.error('[WebShield Popup] Error loading storage:', err);
  }

  // 3. Allowlist Toggle Management
  const isAllowlisted = currentHostname && allowlist.includes(currentHostname);
  updateAllowlistButton(isAllowlisted);

  btnAllowlist.addEventListener('click', async () => {
    if (!currentHostname) return;

    if (isAllowlisted) {
      await chrome.runtime.sendMessage({
        type: 'REMOVE_ALLOWLIST',
        domain: currentHostname
      });
    } else {
      await chrome.runtime.sendMessage({
        type: 'ADD_ALLOWLIST',
        domain: currentHostname
      });
    }

    // Reload popup to display updated state
    window.location.reload();
  });

  function updateAllowlistButton(allowed) {
    if (!currentHostname) {
      btnAllowlist.disabled = true;
      btnAllowlist.textContent = 'Allowlist Domain';
      return;
    }

    if (allowed) {
      btnAllowlist.textContent = `Allowlisted (${currentHostname})`;
      btnAllowlist.classList.add('btn-allowlisted');
      btnAllowlist.title = 'Click to remove this domain from your allowlist';
    } else {
      btnAllowlist.textContent = `+ Allowlist ${currentHostname}`;
      btnAllowlist.classList.remove('btn-allowlisted');
      btnAllowlist.title = 'Click to allowlist this domain and bypass warnings';
    }
  }

  // 4. Render Current Site Evaluation
  const currentRecord = auditLog.slice().reverse().find(entry => entry.url === currentTabUrl);

  if (!currentTabUrl || !isHttpOrHttps(currentTabUrl)) {
    renderCurrentSite({
      score: 0.0,
      tier: 'IGNORED',
      mitreTechnique: 'None',
      reasons: ['Non-HTTP(S) scheme ignored (chrome://, devtools://, file:, about:). Only web schemes are scored.']
    });
  } else if (isAllowlisted) {
    renderCurrentSite({
      score: 0.0,
      tier: 'ALLOWLISTED',
      mitreTechnique: 'N/A (Allowlisted)',
      reasons: ['Domain is present in your trusted allowlist.']
    });
  } else if (currentRecord) {
    renderCurrentSite(currentRecord);
  } else {
    // Default / initial state before navigation event committed
    renderCurrentSite({
      score: 0.0,
      tier: 'LOW',
      mitreTechnique: 'None detected',
      reasons: ['No suspicious indicators detected on this origin.']
    });
  }

  function renderCurrentSite(record) {
    const scorePct = Math.round((record.score || 0) * 100);
    riskScoreEl.textContent = `${scorePct}%`;
    tierLabelEl.textContent = `Tier: ${record.tier}`;
    mitreTagEl.textContent = `MITRE: ${record.mitreTechnique || 'None'}`;

    statusBadge.textContent = record.tier;
    statusBadge.className = 'badge';

    if (record.tier === 'HIGH') {
      statusBadge.classList.add('badge-high');
      riskScoreEl.style.color = 'var(--tier-high)';
    } else if (record.tier === 'MEDIUM') {
      statusBadge.classList.add('badge-medium');
      riskScoreEl.style.color = 'var(--tier-medium)';
    } else if (record.tier === 'ALLOWLISTED') {
      statusBadge.classList.add('badge-allowlisted');
      riskScoreEl.style.color = 'var(--tier-allowlisted)';
    } else if (record.tier === 'IGNORED') {
      statusBadge.classList.add('badge-ignored');
      riskScoreEl.style.color = 'var(--text-muted)';
    } else {
      statusBadge.classList.add('badge-low');
      riskScoreEl.style.color = 'var(--tier-low)';
    }

    // Populate reasons
    reasonsListEl.innerHTML = '';
    if (Array.isArray(record.reasons) && record.reasons.length > 0) {
      record.reasons.forEach(reason => {
        const li = document.createElement('li');
        li.textContent = reason;
        reasonsListEl.appendChild(li);
      });
    } else {
      const li = document.createElement('li');
      li.className = 'reason-empty';
      li.textContent = 'No security anomalies detected on this origin.';
      reasonsListEl.appendChild(li);
    }
  }

  // 5. Render Last 10 Alerts
  alertsCounter.textContent = String(auditLog.length);

  if (auditLog.length > 0) {
    alertsListEl.innerHTML = '';
    const last10 = auditLog.slice(-10).reverse();

    last10.forEach(entry => {
      const li = document.createElement('li');
      li.className = 'alert-item';

      const timeStr = new Date(entry.timestamp).toLocaleTimeString();
      const scorePct = Math.round((entry.score || 0) * 100);
      const tierColor = getTierColor(entry.tier);

      li.innerHTML = `
        <div class="alert-top">
          <span class="alert-tier" style="color: ${tierColor};">[${escapeHtml(entry.tier)}] ${scorePct}%</span>
          <span class="alert-time">${timeStr}</span>
        </div>
        <div class="alert-url" title="${escapeHtml(entry.url)}">${escapeHtml(entry.url)}</div>
        <div class="alert-mitre">${escapeHtml(entry.mitreTechnique || 'T1566: Phishing')}</div>
      `;
      alertsListEl.appendChild(li);
    });
  }

  // 6. Export Alerts as JSON Lines (.jsonl) for SIEM (Wazuh / Splunk)
  btnExport.addEventListener('click', () => {
    if (auditLog.length === 0) {
      alert('No alerts logged yet to export.');
      return;
    }

    // Convert each alert to a clean JSON Line
    const lines = auditLog.map(entry => {
      const exportRecord = {
        timestamp: entry.timestamp,
        url: entry.url,
        score: entry.score,
        tier: entry.tier,
        reasons: entry.reasons || [],
        mitre: entry.mitreTechnique || 'T1566: Phishing'
      };
      return JSON.stringify(exportRecord);
    });

    const jsonlData = lines.join('\n') + '\n';
    const blob = new Blob([jsonlData], { type: 'application/x-ndjson;charset=utf-8' });
    const downloadUrl = URL.createObjectURL(blob);

    const dateStr = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `webshield_alerts_${dateStr}.jsonl`;

    const downloadLink = document.createElement('a');
    downloadLink.href = downloadUrl;
    downloadLink.download = filename;
    document.body.appendChild(downloadLink);
    downloadLink.click();
    document.body.removeChild(downloadLink);

    setTimeout(() => {
      URL.revokeObjectURL(downloadUrl);
    }, 1000);
  });

  function getTierColor(tier) {
    if (tier === 'HIGH') return 'var(--tier-high)';
    if (tier === 'MEDIUM') return 'var(--tier-medium)';
    if (tier === 'ALLOWLISTED') return 'var(--tier-allowlisted)';
    return 'var(--tier-low)';
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>'"]/g, tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag));
  }
});
