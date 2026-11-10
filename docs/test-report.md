# WebShield Test & Evaluation Report

This document records the empirical evaluation, automated unit test results, manual test procedures for local fixtures, false-positive checklists on popular web properties, held-out test set analysis (including false-negative failure mode analysis), and structural architectural limitations.

---

## 1. Automated Unit Test Results

All test suites execute 100% locally with zero external network connectivity or cloud dependencies.

### Summary Table

| Test Suite File | Engine / Runtime | Tests Ran | Passed | Failed | Duration | Scope |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| [`tests/test_features_rules.js`](file:///E:/webshield-extension/tests/test_features_rules.js) | Node.js | 16 | 16 | 0 | ~15 ms | Feature extraction accuracy & heuristic rule engine |
| [`tests/test_headers.js`](file:///E:/webshield-extension/tests/test_headers.js) | Node.js | 5 | 5 | 0 | ~8 ms | Security header analysis & zero-cookie content privacy |
| [`tests/test_dom_heuristics.js`](file:///E:/webshield-extension/tests/test_dom_heuristics.js) | Node.js | 4 | 4 | 0 | ~10 ms | Cross-domain form logic & AST `.value` privacy audit |
| [`tests/test_model_verification.js`](file:///E:/webshield-extension/tests/test_model_verification.js) | Node.js | 20 | 20 | 0 | ~25 ms | JSON size (<1 MB) & JS vs. Python ML probability parity |
| [`tests/test_risk_engine.js`](file:///E:/webshield-extension/tests/test_risk_engine.js) | Node.js | 8 | 8 | 0 | ~12 ms | Unified scoring, tiering, allowlist bypass & MITRE tags |
| [`tests/test_jsonl_export.js`](file:///E:/webshield-extension/tests/test_jsonl_export.js) | Node.js | 2 | 2 | 0 | ~6 ms | SIEM NDJSON export formatting for Wazuh / Splunk |
| [`tests/test_feature_parity.py`](file:///E:/webshield-extension/tests/test_feature_parity.py) | Python 3.13 + Node | 1 | 1 | 0 | ~1.15 s | 15-feature cross-engine mathematical equality |
| [`tests/test_url_features.py`](file:///E:/webshield-extension/tests/test_url_features.py) | Python 3.13 | 2 | 2 | 0 | ~1 ms | Standard Python feature dictionary checks |
| **Total Automated Coverage** | **Multi-Runtime** | **58** | **58** | **0** | **~1.25 s** | **100% Passing Rate** |

---

## 2. Feature-by-Feature Manual Test Table (Local Test Pages)

Serve local test pages using:
```powershell
python -m http.server 8080 --directory E:\webshield-extension
```
*(Leave the **Observed Tier**, **Observed Score**, and **Pass/Fail** columns blank for your manual inspection records).*

| Test Scenario | Test Page File / URL | Expected Detection Findings | Expected Tier | Manual Test Status | Observed Score | Observed Tier | Pass / Fail | Notes |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Cross-Domain Password Submission** | [`cross_origin_form.html`](file:///E:/webshield-extension/tests/pages/cross_origin_form.html)<br>`http://localhost:8080/tests/pages/cross_origin_form.html` | - Password form action submits to different domain (`attacker-harvest.example.org`)<br>- Insecure HTTP password input | **HIGH** (immediate risk) | [ ] | | | | |
| **Insecure HTTP Password Form** | [`http_password.html`](file:///E:/webshield-extension/tests/pages/http_password.html)<br>`http://localhost:8080/tests/pages/http_password.html` | - Password input detected on unencrypted HTTP page | **MEDIUM** or **HIGH** | [ ] | | | | |
| **Hidden Iframe & Nested Form** | [`hidden_iframe.html`](file:///E:/webshield-extension/tests/pages/hidden_iframe.html)<br>`http://localhost:8080/tests/pages/hidden_iframe.html` | - Hidden iframe detected on page (`about:blank`)<br>- Hidden iframe detected (`iframe_password.html`)<br>- Password input embedded in hidden iframe | **HIGH** | [ ] | | | | |
| **Mixed Content Resources** | [`mixed_content.html`](file:///E:/webshield-extension/tests/pages/mixed_content.html)<br>`http://localhost:8080/tests/pages/mixed_content.html` | - Unencrypted HTTP images/frames on secure origin | **LOW** / **MEDIUM** | [ ] | | | | |
| **Benign Baseline HTML** | [`safe_sample.html`](file:///E:/webshield-extension/tests/pages/safe_sample.html)<br>`http://localhost:8080/tests/pages/safe_sample.html` | - No suspicious indicators | **LOW** (Safe) | [ ] | | | | |
| **Synthetic Phishing Simulation** | [`phishing_simulation.html`](file:///E:/webshield-extension/tests/pages/phishing_simulation.html)<br>`http://localhost:8080/tests/pages/phishing_simulation.html` | - Baseline inspection fixture | **LOW** | [ ] | | | | |

---

## 3. False-Positive Testing: 20 Popular Websites

Navigate to each site in your browser with WebShield active. Record the observed score and tier in the blank fields below to confirm whether legitimate web operations trigger false alarms.

| # | Domain Name | Target URL | Expected Tier | Observed Tier | Observed Score (%) | False Positive? (Y/N) | Findings / Notes |
| :-: | :--- | :--- | :-: | :---: | :---: | :---: | :--- |
| 1 | **Google** | `https://www.google.com/` | LOW | | | | |
| 2 | **Wikipedia** | `https://en.wikipedia.org/wiki/Main_Page` | LOW | | | | |
| 3 | **GitHub** | `https://github.com/` | LOW | | | | |
| 4 | **Amazon** | `https://www.amazon.com/` | LOW | | | | |
| 5 | **YouTube** | `https://www.youtube.com/` | LOW | | | | |
| 6 | **Stack Overflow** | `https://stackoverflow.com/` | LOW | | | | |
| 7 | **Reddit** | `https://www.reddit.com/` | LOW | | | | |
| 8 | **LinkedIn** | `https://www.linkedin.com/` | LOW | | | | |
| 9 | **Microsoft** | `https://www.microsoft.com/` | LOW | | | | |
| 10 | **Apple** | `https://www.apple.com/` | LOW | | | | |
| 11 | **Cloudflare** | `https://www.cloudflare.com/` | LOW | | | | |
| 12 | **Mozilla** | `https://www.mozilla.org/` | LOW | | | | |
| 13 | **Python Foundation**| `https://www.python.org/` | LOW | | | | |
| 14 | **New York Times** | `https://www.nytimes.com/` | LOW | | | | |
| 15 | **BBC** | `https://www.bbc.com/` | LOW | | | | |
| 16 | **CNN** | `https://www.cnn.com/` | LOW | | | | |
| 17 | **Craigslist** | `https://www.craigslist.org/about/` | LOW | | | | |
| 18 | **IMDb** | `https://www.imdb.com/` | LOW | | | | |
| 19 | **ESPN** | `https://www.espn.com/` | LOW | | | | |
| 20 | **Internet Archive**| `https://archive.org/` | LOW | | | | |

---

## 4. False-Negative Testing: Held-Out Test Set URLs

The table below presents real empirical data extracted from the held-out test split (`sample_20_eval.json`). It highlights both **high-confidence detections** and **model misses** (false negatives), showing how different threat vectors behave under pure URL-based lexical classification.

### A. High-Confidence Detections (True Positives)

These URLs exhibit aggressive lexical anomalies (excessive length, high dot counts, deceptive brand keywords in subdomains, or obfuscated query parameters):

| # | Held-Out Phishing URL | Actual Label | ML Phish Prob | Detected Risk Indicators | In-Browser Action | Manual Verified [ ] |
| :-: | :--- | :-: | :-: | :--- | :---: | :-: |
| 1 | `paypal-com.us.webscrlcmdl.login.submit.dispatch...ahbabarab.com/...` | Phishing (`1`) | **99.94%** | Brand keywords (`paypal`, `login`), 11 dots, 9 subdomains | **HIGH** (Blocked by warning page) | [ ] |
| 2 | `'home.comcast.net/~lucinda.peterson/?login=done...` | Phishing (`1`) | **99.37%** | Excessive length (564 chars), 36 dots, brand keyword (`login`) | **HIGH** (Blocked by warning page) | [ ] |
| 3 | `www.cnhedge.cn/js/index.htm?us.battle.net/login/en/?ref=...` | Phishing (`1`) | **99.23%** | Brand keyword (`login`) in query string, 7 dots, subdomains | **HIGH** (Blocked by warning page) | [ ] |
| 4 | `ams1.ib.adnxs.com/if?enc=m5mZmZmZuT80MzMzMzOzPx...` | Phishing (`1`) | **89.43%** | Abnormally long URL (613 chars), 8 dots, elevated entropy | **HIGH** (Blocked by warning page) | [ ] |

---

### B. Subtle Threats & Model Misses (False Negatives on Pure Lexical Features)

When attackers host credential harvesting kits on compromised personal domains or short clean paths, the lexical structure appears indistinguishable from standard blogs:

| # | Held-Out Phishing URL | Actual Label | ML Phish Prob | Why the Pure Lexical Model Missed It (Root Cause) | Defense-in-Depth Mitigation | Manual Verified [ ] |
| :-: | :--- | :-: | :-: | :--- | :--- | :-: |
| 1 | `u16018424.onlinehome-server.com/norkdk/` | Phishing (`1`) | **17.34%** | Hosted on standard hosting provider with short generic path (`/norkdk/`). Lacks brand keywords or abusive TLD. | In-page DOM scanner inspects destination of login forms if present. | [ ] |
| 2 | `kramarzanna.republika.pl/trregrq` | Phishing (`1`) | **16.93%** | Short URL (32 chars), 2 dots, standard `.pl` ccTLD, no brand keywords. | Content script flags credential inputs submitting across domains. | [ ] |
| 3 | `rishtapoint.com/aol/` | Phishing (`1`) | **19.66%** | Extremely short URL (20 chars), 1 dot, standard `.com`. Keyword `aol` is not in default top-7 brand list. | Can be added to expanded keyword dictionary or flagged via DOM scanner. | [ ] |
| 4 | `spinsinergi.com/pay/` | Phishing (`1`) | **19.66%** | Minimalist path (`/pay/`), standard domain length, zero special characters. | Header inspector flags missing defensive security headers (CSP, HSTS). | [ ] |
| 5 | `geninmun.com/srbe/srbe.php` | Phishing (`1`) | **14.55%** | Standard 2-level path with `.php` file extension. Matches benign site structural distributions. | DOM script detects password fields on unencrypted connections. | [ ] |
| 6 | `techdryindia.com/ours/cc/home/` | Phishing (`1`) | **15.21%** | Generic directory path (`/ours/cc/home/`), low digit count, standard `.com`. | Form inspection flags cross-origin credential posting. | [ ] |

---

## 5. Architectural & Operational Limitations

To maintain strict educational safety, lightweight local performance (~6 GB RAM), and total privacy, WebShield operates within specific architectural boundaries:

### 1. No Raw Packet or Transport Inspection
* **Limitation:** WebShield executes inside Chrome user-space as a WebExtension. It cannot inspect raw TCP/IP packets, TLS handshake records, cipher suite negotiations, or rogue root CA certificates.
* **Impact:** Man-in-the-Middle (MITM) attacks with installed root certificates or TLS interception proxies are undetectable at this extension layer.

### 2. Zero Response-Body Inspection (Privacy Guardrail)
* **Limitation:** Under **Project Rule 6**, WebShield strictly avoids reading, parsing, or storing inner page text, form values, session cookies, or response body payloads.
* **Impact:** Phishing kits that exactly replicate corporate logos, text, or CSS styling on unbranded, benign-looking URLs cannot be identified via visual or content similarity matching.

### 3. Manifest V3 Service Worker Lifecycle Constraints
* **Limitation:** Manifest V3 background service workers are ephemeral processes that terminate after ~30 seconds of browser inactivity.
* **Impact:** No persistent in-memory global state can be retained. All evaluation state, allowlists, and the 500-entry audit log must be read and written asynchronously via `chrome.storage.local`.

### 4. Offline Domain Age & WHOIS Unavailability
* **Limitation:** Newly registered domains (NRDs) under 24–48 hours old represent a primary phishing delivery vehicle. Querying domain registration age requires contacting external WHOIS / RDAP servers.
* **Impact:** Under **Project Rule 2** (strictly 100% offline, zero external network requests), domain registration age cannot be queried and cannot serve as an offline heuristic.

### 5. Dataset Bias & Potential False Positives
* **Limitation:** Supervised models trained on public datasets (e.g. Kaggle / PhiUSIIL) reflect historical phishing campaigns that relied heavily on long URLs, multiple subdomains, and specific brand strings.
* **Impact:** Complex legitimate enterprise URLs (such as OAuth redirect endpoints, AWS S3 presigned URLs, CDN tracking links, or deep SharePoint paths) exhibit elevated character counts, dots, and hyphens that may trigger false-positive alerts unless allowlisted by the user.
