# WebShield: Autonomous In-Browser Phishing & URL Risk Detection

A lightweight, 100% local, privacy-first Google Chrome extension designed for defensive cybersecurity education and web threat mitigation.

WebShield detects malicious URLs, deceptive domain structures, insecure forms, and missing transport security headers entirely inside the browser runtime—without cloud APIs, remote servers, or external telemetry.

---

## 1. Problem Statement

Phishing and deceptive links remain the primary initial access vector across modern cyberattacks ([MITRE ATT&CK T1566](https://attack.mitre.org/techniques/T1566/)). Traditional browser protections and commercial endpoint security tools typically rely on **cloud reputation lookups**, transmitting every URL visited by the user to remote servers. This introduces:
1. **Privacy Risks:** Sensitive query parameters, private intranet paths, and browsing habits are exposed to external logging.
2. **Network Latency & Dependency:** Threat lookups fail when operating offline, in air-gapped systems, or on unstable connections.
3. **Resource Overhead:** Bulky endpoint agents and background daemons consume excessive memory and battery.

**WebShield solves this** by executing multi-layered detection (heuristic analysis, in-browser machine learning inference, response header verification, and DOM form structural inspection) strictly on the local client machine, keeping all data isolated within the browser.

---

## 2. Architecture

```mermaid
flowchart TD
    subgraph Browser Navigation
        A[Navigation Commit / URL Event] --> B[URL Parser & Normalizer]
    end

    subgraph Parallel Local Engines
        B --> C[Lexical & Heuristic Engine<br/><code>features.js</code> & <code>rules.js</code>]
        B --> D[Offline Random Forest Engine<br/><code>model.js</code> + <code>rf_model.json</code>]
        A --> E[Security Headers Inspector<br/><code>headers.js</code> (Read-Only)]
        A --> F[Content Script DOM Scanner<br/><code>content.js</code> (Structural Only)]
    end

    subgraph Decision & Audit
        C --> G[Unified Risk Engine<br/><code>risk_engine.js</code> & <code>config.js</code>]
        D --> G
        E --> G
        F --> G
        H[User Site Allowlist<br/><code>chrome.storage.local</code>] --> G
        G --> I[Audit Log<br/>Capped at 500 Entries]
    end

    subgraph Tiered Actions
        G -->|Score < 0.40| J[LOW Tier: Log Only]
        G -->|0.40 <= Score < 0.70| K[MEDIUM Tier: Badge + Notification]
        G -->|Score >= 0.70 or Critical DOM| L[HIGH Tier: Warning Redirect<br/><code>warning.html</code>]
    end

    subgraph SIEM Integration
        I --> M[JSON Lines Export<br/><code>.jsonl</code> for Wazuh / Splunk]
    end
```

---

## 3. Key Features

- **Lexical URL Feature Extraction:** Extracts 14 numerical and structural features in sub-millisecond time (`urlLength`, `hostnameLength`, `dotCount`, `subdomainCount`, `hyphenCount`, `@` symbol, IP address host, digit ratio, special character count, Punycode/homographs, HTTPS protocol, suspicious TLDs, brand keywords, and path depth).
- **In-Browser Random Forest Inference:** Evaluates a 30-tree ensemble exported directly into nested array primitives (`[feature, threshold, left, right, prob]`) in microseconds without TensorFlow, ONNX, or external runtimes.
- **Read-Only Security Headers Inspection:** Passively audits response headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`) and verifies cookie flags (`Secure`, `HttpOnly`) without storing credentials.
- **Structural In-Page DOM Form Scanner:** Identifies password inputs submitting to a different registrable domain, passwords on unencrypted HTTP pages, and forms inside hidden/cross-origin `<iframe>` elements.
- **User-Managed Site Allowlist:** Quick-toggle allowlist stored in `chrome.storage.local` to immediately bypass false positives.
- **SIEM-Ready NDJSON Export:** One-click export downloading the 500-entry audit log as standard JSON Lines (`.jsonl`) ready for ingestion into **Wazuh**, **Splunk**, or Elastic.

---

## 4. Detection Capabilities & MITRE ATT&CK Mapping

| Threat Vector | Detection Mechanism | Primary MITRE ATT&CK Technique | Risk Tier |
| :--- | :--- | :--- | :---: |
| **Brand Impersonation / Typosquatting** | Brand keywords (`paypal`, `login`, `bank`, etc.) in subdomains or path | **[T1566.002: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)** | HIGH |
| **Punycode / Homograph Deception** | Internationalized Domain Name (IDN) `xn--` lookalikes | **[T1566: Phishing](https://attack.mitre.org/techniques/T1566/)** | HIGH |
| **Raw IP Host Usage** | Direct IPv4/IPv6 address used in place of domain name | **[T1566.002: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)** | HIGH |
| **Cross-Domain Password Harvesting** | Form action submits credentials to external registrable domain | **[T1552: Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)** | HIGH |
| **Hidden Iframe / Clickjacking** | Zero-dimension or styled hidden frames embedding forms | **[T1204.001: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)** | HIGH |
| **Unencrypted Credential Input** | Password fields loaded over plain HTTP connections | *None (Transport Hygiene)* | MEDIUM |
| **Suspicious Disposable TLDs** | High-abuse TLDs (`.xyz`, `.top`, `.click`, `.tk`, etc.) | **[T1566.002: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)** | MEDIUM |
| **Missing Defensive Headers** | Absence of CSP, HSTS, XFO, or `nosniff` on main-frame origins | *None (Configuration Hygiene)* | LOW |

---

## 5. Machine Learning Model Performance

The offline model was trained on **549,346 raw URLs** (cleaned to 507,192 unique entries) with a memory-safe stratified sample of 50,000 URLs to respect ~6 GB RAM environments.

### Real Test Set Evaluation (10,000 Held-Out URLs)

| Model Architecture | Hyperparameters | Accuracy | Precision | Recall | F1 Score | Training Time |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression Baseline** | `max_iter=1000` | 85.90% | 93.14% | 40.39% | 0.5635 | 3.05s |
| **Random Forest (WebShield)** | `30 trees, max_depth=8` | **86.26%** | **94.26%** | **41.54%** | **0.5767** | **0.57s** |

### Confusion Matrix (Random Forest on Held-Out Test Set)
```text
                  Predicted Benign    Predicted Phishing
Actual Benign          7,690                  57    (0.7% False Positive Rate)
Actual Phishing        1,317                 936    (High Precision, Conservative Recall)
```

### Top Feature Importances
1. `brandKeywordsCount`: **0.3136**
2. `dotCount`: **0.1891**
3. `urlLength`: **0.1147**
4. `digitRatio`: **0.0811**
5. `hyphenCount`: **0.0590**
6. `subdomainCount`: **0.0479**

### Model Size Verification
- Path: `extension/model/rf_model.json`
- Serialized Size: **116.87 KB** (well within the 1 MB budget constraint).

---

## 6. Installation & Quick Start

### Step 1: Load Extension into Chrome
1. Open Google Chrome and enter `chrome://extensions/` in the address bar.
2. Enable **Developer mode** using the toggle switch in the upper-right corner.
3. Click **Load unpacked** (top-left) and select the extension folder:
   ```text
   E:\webshield-extension\extension
   ```
4. Pin the **WebShield** shield icon to your Chrome toolbar.

### Step 2: Run Automated Tests
Execute the automated test suite locally:
```powershell
cd E:\webshield-extension
node tests/test_features_rules.js
node tests/test_headers.js
node tests/test_dom_heuristics.js
node tests/test_model_verification.js
node tests/test_risk_engine.js
node tests/test_jsonl_export.js
python tests/test_feature_parity.py
python -m unittest tests/test_url_features.py
```
*(All 58 tests will execute and pass within ~1.5 seconds).*

### Step 3: Test Local Scenarios
Start a local HTTP test server:
```powershell
python -m http.server 8080 --directory E:\webshield-extension
```
- Open `http://localhost:8080/tests/pages/cross_origin_form.html` to observe high-risk credential form blocking.
- Open `http://localhost:8080/tests/pages/hidden_iframe.html` to observe hidden iframe detection.
- Click the extension icon and click **`💾 Export Alerts (.jsonl)`** to download your SIEM audit log.

---

## 7. Privacy Guarantees (Project Rules 2 & 6)

- **Zero Cloud Communication:** WebShield makes **zero network requests** of its own. It uses no telemetry, no Google Analytics, no external API calls, and no remote weight downloads.
- **Zero DOM / Credential Logging:** WebShield strictly never reads, accesses, or records `.value` properties, form inputs, session cookies, or keystrokes.
- **Strict Storage Bounds:** All logs are maintained exclusively in `chrome.storage.local` on your local hard drive, with hard FIFO caps:
  - Navigation log: capped at 200 items.
  - Audit log: capped at 500 items.
  - Header hosts: capped at 100 hostnames.

---

## 8. Architectural Limitations

1. **No Raw Packet / TLS Transport Inspection:** Operates inside Chrome application user-space. Cannot inspect TCP/IP packet streams or validate TLS certificate chains against rogue root CAs.
2. **No Response-Body Parsing:** In order to uphold zero-credential privacy (Rule 6), WebShield does not inspect full HTML body contents or server-rendered visuals. Phishing forms mimicking brands on benign, unrelated domains without lexical anomalies cannot be detected by URL features alone.
3. **Manifest V3 Ephemeral Lifecycle:** Service workers terminate after ~30 seconds of inactivity. All state must be loaded asynchronously from `chrome.storage.local`.
4. **Offline Domain Age Limitation:** Newly registered domains (NRDs) represent a primary attack vector. Because WHOIS and RDAP lookups require external outbound network calls, registration dates cannot be queried offline.
5. **Dataset Bias:** Supervised models trained on historical public corpora may trigger elevated scores on complex legitimate URLs containing deep tracking query parameters (e.g. presigned S3 URLs, OAuth redirects). The user allowlist mitigates this.

---

## 9. Future Work

- **Native Messaging SIEM Forwarder:** Lightweight local daemon using Chrome Native Messaging to pipe audit logs directly to a local Wazuh agent (`ossec.log` / `wazuh-agent`) or local syslog daemon without touching external networks.
- **Offline High-Risk Domain Bloom Filters:** Pre-compiled, highly compressed bloom filters (~2 MB) of known malicious root domains generated offline and packaged with the extension.
- **Local Domain Age Cache:** Optional, user-approved local DNS/WHOIS resolution bridge for air-gapped security operations centers.

---

## 10. Recommended Screenshots Checklist

Save the following captures to [`screenshots/`](file:///E:/webshield-extension/screenshots/):

| Filename | Description | Trigger Flow |
| :--- | :--- | :--- |
| `01_popup_safe.png` | WebShield popup on a clean website showing green `SAFE / LOW` status (`0%`). | Open `https://example.com/` and open popup. |
| `02_warning_redirect.png` | Full-screen blocking warning page (`warning.html`) displaying alert banner, blocked URL, MITRE badge, reasons, and buttons. | Navigate to `http://paypal.account-verification.example.xyz/login/verify`. |
| `03_popup_medium_alert.png` | Popup showing amber `MEDIUM` risk tier badge and desktop notification. | Navigate to an unhardened page with subdomains or HTTP password. |
| `04_cross_domain_dom_alert.png` | Popup or service worker console showing DOM scanner flagging cross-domain password form. | Open `http://localhost:8080/tests/pages/cross_origin_form.html`. |
| `05_allowlist_toggle.png` | Popup displaying trusted domain with cyan `ALLOWLISTED` badge. | Click `+ Allowlist Domain` in popup on any site. |
| `06_siem_jsonl_export.png` | Recent alerts feed and exported `.jsonl` audit log open in text editor showing structured Wazuh/Splunk records. | Click `💾 Export Alerts (.jsonl)` and inspect file. |

---

## 11. What I Learned

1. **Manifest V3 Service Worker Disciplines:** Building a security extension in Manifest V3 requires completely eliminating global in-memory state. Transitioning to asynchronous, bounded `chrome.storage.local` FIFO buffers ensures seamless operation across worker sleep/wake lifecycles.
2. **Cross-Engine Parity Engineering:** Guaranteeing exact mathematical equivalence between Python feature extractors and in-browser JavaScript engines is essential for training offline models that generalize reliably to live browser traffic.
3. **Array-Primitive Model Compression:** Exporting decision trees as nested array primitives (`[feat, thresh, left, right, prob]`) rather than object graphs compressed a 30-tree Random Forest to **116.87 KB**, executing in microseconds without external ML libraries.
4. **Privacy-Preserving Defensive Engineering:** Proving that client-side security tools can provide robust phishing protection without inspecting user passwords or transmitting personal browsing telemetry.

---

## 12. License

Distributed under the [MIT License](LICENSE).
