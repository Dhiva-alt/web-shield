"""
WebShield - Unit Tests for URL Feature Extraction (Skeleton)

Uses Python's standard library `unittest` module (zero external dependencies).
"""

import unittest
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ml"))
from features import extract_features


class TestURLFeatureExtraction(unittest.TestCase):
    def test_extract_url_features_length(self):
        url = "https://example.com/login"
        features = extract_features(url)
        self.assertIn("urlLength", features)
        self.assertEqual(features["urlLength"], len(url))

    def test_extract_url_features_dots(self):
        url = "https://sub.sub2.example.com"
        features = extract_features(url)
        self.assertIn("dotCount", features)
        self.assertEqual(features["dotCount"], 3)


if __name__ == "__main__":
    unittest.main()
