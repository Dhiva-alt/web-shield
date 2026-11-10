"""
WebShield - Test Suite for JS vs. Python Feature Parity

Compares output of extension/lib/features.js (via Node.js) against
ml/features.py (Python) to guarantee 100% mathematical parity across environments.
"""

import json
import subprocess
import unittest
from pathlib import Path
import sys

# Add ml/ directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ml"))
from features import extract_features as py_extract_features

PROJECT_ROOT = Path(__file__).resolve().parent.parent

BENCHMARK_URLS = [
    "https://example.com/",
    "http://192.168.1.100:8080/login",
    "https://paypal.secure-verification.example.xyz/account/login/verify",
    "http://example.com@phish-gateway.example.top/verify?token=12345",
    "https://xn--pple-43d.example.com/bank/verify",
    "http://secure-login-account-update-bank.sub1.sub2.example.click/9876543210/confirm",
    "https://sub.portal.google.com/test",
    "https://login.service.com.au/verify-identity",
    "http://my-insecure-site.work/path1/path2/path3/path4/path5",
]


def get_js_features(url: str) -> dict:
    """Executes Node.js to extract features from extension/lib/features.js."""
    js_code = f"""
    const {{ extractFeatures }} = require('./extension/lib/features.js');
    const f = extractFeatures({json.dumps(url)});
    // Normalize JS boolean/strings to numerical representation matching Python ML schema
    const normalized = {{
      urlLength: f.urlLength,
      hostnameLength: f.hostnameLength,
      dotCount: f.dotCount,
      subdomainCount: f.subdomainCount,
      hyphenCount: f.hyphenCount,
      hasAtSymbol: f.hasAtSymbol ? 1 : 0,
      isIpAddress: f.isIpAddress ? 1 : 0,
      digitRatio: f.digitRatio,
      specialCharCount: f.specialCharCount,
      hasPunycodeOrNonAscii: f.hasPunycodeOrNonAscii ? 1 : 0,
      isHttps: f.isHttps ? 1 : 0,
      suspiciousTld: f.suspiciousTld ? 1 : 0,
      brandKeywordsCount: f.brandKeywordsFound ? f.brandKeywordsFound.length : 0,
      pathDepth: f.pathDepth,
      isValidUrl: f.isValidUrl ? 1 : 0
    }};
    console.log(JSON.stringify(normalized));
    """
    proc = subprocess.run(
        ["node", "-e", js_code],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout.strip())


class TestFeatureParity(unittest.TestCase):
    def test_js_python_feature_parity(self):
        print("\n============================================================")
        print(" WebShield Feature Parity Audit: Node.js vs. Python")
        print("============================================================\n")

        for url in BENCHMARK_URLS:
            js_feat = get_js_features(url)
            py_feat = py_extract_features(url)

            print(f"[*] Testing URL: {url}")
            for key in js_feat:
                js_val = js_feat[key]
                py_val = py_feat[key]
                self.assertEqual(
                    js_val,
                    py_val,
                    f"Mismatch on feature '{key}' for URL '{url}': JS={js_val} vs PY={py_val}",
                )
            print(f"    -> All {len(js_feat)} features match perfectly.")

        print("\n[OK] 100% Feature Parity verified between JS and Python.\n")


if __name__ == "__main__":
    unittest.main()
