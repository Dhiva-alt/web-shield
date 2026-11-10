# Screenshots Guide

This directory holds visual demonstration screenshots for documentation and portfolio presentation.

### Recommended Screenshots Checklist

| Filename | Description | How to Capture |
| :--- | :--- | :--- |
| `01_popup_safe.png` | WebShield popup on a legitimate site showing green `SAFE / LOW` status (`0%`). | Open `https://example.com/`, click WebShield extension icon, capture popup. |
| `02_warning_redirect.png` | Full-screen blocking warning page (`warning.html`) displaying red high-risk alert banner, blocked URL, MITRE technique tag, reasons, and action buttons. | Navigate to `http://paypal.account-verification.example.xyz/login/verify` to trigger redirect. |
| `03_popup_medium_alert.png` | Popup showing amber `MEDIUM` risk tier badge and desktop notification. | Navigate to an unhardened page with multiple subdomains or HTTP password. |
| `04_cross_domain_dom_alert.png` | Popup or background DevTools console showing DOM scanner flagging a cross-domain password submission. | Open `http://localhost:8080/tests/pages/cross_origin_form.html`. |
| `05_allowlist_toggle.png` | Popup displaying trusted domain with cyan `ALLOWLISTED` badge. | Click `+ Allowlist Domain` in the popup on any site. |
| `06_siem_jsonl_export.png` | Recent alerts feed and exported `.jsonl` audit log open in text editor (VS Code / Notepad) showing structured SIEM records. | Click `💾 Export Alerts (.jsonl)` in the popup and open the downloaded file. |
