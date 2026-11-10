# Chrome Extension Permissions Rationale

This document details all Chrome permissions requested by the WebShield extension, the functional rationale for each, and the security/privacy safeguards enforced.

---

## Principle of Least Privilege & Local Safeguards

WebShield is designed under strict privacy and defensibility rules:
- **Zero Remote Network Access:** Although `<all_urls>` is declared in `host_permissions` to monitor in-browser navigation and request headers locally, WebShield makes **no external outbound network requests** (no remote telemetry, no cloud APIs).
- **Zero DOM / Credential Inspection:** WebShield does **not** read form inputs, keystrokes, page body content, cookies, or typed passwords (Project Rules 2 & 6).
- **Stateless Background Execution:** Manifest V3 service worker stores no global in-memory state; all evaluation records and navigation buffers are maintained in `chrome.storage.local`.

---

## Requested Permissions

### 1. `webNavigation`
* **Type:** API Permission
* **Purpose:** Detects main-frame navigation commitments (`chrome.webNavigation.onCommitted`, `frameId === 0`).
* **Usage in WebShield:**
  - Extracts the top-level URL, tab ID, and timestamp when the browser begins rendering a committed main-frame document.
  - Ensures reliable navigation tracking across redirects.

### 2. `webRequest`
* **Type:** API Permission
* **Purpose:** Enables inspection of network request metadata (headers, redirect chains, IP endpoints).
* **Usage in WebShield:**
  - Analyzes structural headers and redirection anomalies locally.
  - Does not inspect payload body data or credentials.

### 3. `storage`
* **Type:** API Permission
* **Purpose:** Persists local operational state using `chrome.storage.local`.
* **Usage in WebShield:**
  - Stores a FIFO ring buffer of up to the last 200 main-frame navigations (`{ url, tabId, timestamp }`).
  - Stores local risk scores, heuristic flags, and user notification preferences.
  - All data is stored purely on the local disk; `chrome.storage.sync` is never used.

### 4. `tabs`
* **Type:** API Permission
* **Purpose:** Provides access to tab lifecycle information.
* **Usage in WebShield:**
  - Correlates navigation events with open browser tabs to update the badge/popup for the user's active tab.

### 5. `notifications`
* **Type:** API Permission
* **Purpose:** Triggers native desktop/browser notifications when high-risk URLs are encountered.
* **Usage in WebShield:**
  - Informs the user immediately when an anomalous or high-risk domain is opened, even if the popup is closed.

### 6. `host_permissions: ["<all_urls>"]`
* **Type:** Host Permission
* **Purpose:** Grants the browser extension access to monitor web request headers and navigation events across all web origins.
* **Guarantees:**
  - Used strictly for passive local URL feature analysis.
  - The extension initiates zero outbound HTTP/HTTPS requests to external endpoints.
