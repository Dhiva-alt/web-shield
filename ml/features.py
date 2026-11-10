"""
WebShield - Python URL Feature Extractor
Exact Python reimplementation of extension/lib/features.js.

Privacy Guarantee:
- Pure offline lexical/statistical string extraction.
- Zero network requests, zero page inspection.
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    'tk', 'xyz', 'top', 'click', 'gq', 'ml', 'cf', 'ga',
    'buzz', 'fit', 'rest', 'work', 'download', 'surf', 'loan'
}

BRAND_KEYWORDS = [
    'paypal',
    'google',
    'microsoft',
    'bank',
    'login',
    'verify',
    'secure'
]

IPV4_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$'
)
IPV6_REGEX = re.compile(r'^(?:\[)?[0-9a-fA-F:]+(?:\])?$')
SPECIAL_CHARS_REGEX = re.compile(r'[-_.~!*\'();:@&=+$,/?%#[\]]')


def parse_url(url_str: str):
    """
    Safely parses URL string, matching the JS URL constructor behavior.
    """
    if not isinstance(url_str, str):
        return None
    trimmed = url_str.strip()
    if not trimmed:
        return None

    try:
        if "://" not in trimmed:
            trimmed = "http://" + trimmed
        parsed = urlparse(trimmed)
        if not parsed.netloc and not parsed.path:
            return None
        return parsed
    except Exception:
        return None


def extract_features(url_str: str) -> dict:
    """
    Extracts numerical and structural features from a URL string,
    matching extension/lib/features.js field for field.
    """
    raw_url = (url_str or "").strip()
    parsed = parse_url(raw_url)

    if not parsed or not parsed.hostname:
        return {
            "urlLength": len(raw_url),
            "hostnameLength": 0,
            "dotCount": raw_url.count("."),
            "subdomainCount": 0,
            "hyphenCount": raw_url.count("-"),
            "hasAtSymbol": int("@" in raw_url),
            "isIpAddress": 0,
            "digitRatio": 0.0,
            "specialCharCount": len(SPECIAL_CHARS_REGEX.findall(raw_url)),
            "hasPunycodeOrNonAscii": 0,
            "isHttps": 0,
            "suspiciousTld": 0,
            "brandKeywordsCount": 0,
            "pathDepth": 0,
            "isValidUrl": 0,
            "hostname": ""
        }

    hostname = (parsed.hostname or "").lower()
    pathname = parsed.path or ""
    query = parsed.query or ""
    protocol = (parsed.scheme or "").lower()

    # 1. Lengths
    url_length = len(raw_url)
    hostname_length = len(hostname)

    # 2. Dots across full URL
    dot_count = raw_url.count(".")

    # 3. IP address check
    is_ipv4 = bool(IPV4_REGEX.match(hostname))
    is_ipv6 = bool(IPV6_REGEX.match(hostname) and ":" in hostname)
    is_ip_address = int(is_ipv4 or is_ipv6)

    # 4. Subdomain calculation
    subdomain_count = 0
    tld = ""
    main_domain = ""

    if not is_ip_address and "." in hostname:
        host_parts = hostname.split(".")
        tld = host_parts[-1]

        is_two_part_suffix = len(host_parts) >= 3 and host_parts[-2] in ("co", "com")
        domain_parts_count = 3 if is_two_part_suffix else 2

        if len(host_parts) > domain_parts_count:
            subdomain_count = len(host_parts) - domain_parts_count
            main_domain = host_parts[-domain_parts_count]
        elif len(host_parts) >= 2:
            main_domain = host_parts[0]

    # 5. Hyphen count
    hyphen_count = raw_url.count("-")

    # 6. @ symbol
    has_at_symbol = int("@" in raw_url)

    # 7. Digit ratio
    digits = sum(1 for c in raw_url if c.isdigit())
    digit_ratio = round(digits / url_length, 4) if url_length > 0 else 0.0

    # 8. Special characters count
    special_char_count = len(SPECIAL_CHARS_REGEX.findall(raw_url))

    # 9. Punycode or non-ASCII
    has_punycode = hostname.startswith("xn--") or ".xn--" in hostname
    has_non_ascii = any(ord(c) > 127 for c in hostname)
    has_punycode_or_non_ascii = int(has_punycode or has_non_ascii)

    # 10. HTTPS check
    is_https = int(protocol == "https")

    # 11. Suspicious TLD
    suspicious_tld = int(tld in SUSPICIOUS_TLDS) if tld else 0

    # 12. Brand keywords in subdomain or path/query (outside root domain)
    subdomains_string = ".".join(hostname.split(".")[:subdomain_count])
    path_and_query = (pathname + ("?" + query if query else "")).lower()
    brand_keywords_count = 0

    for brand in BRAND_KEYWORDS:
        in_subdomain = brand in subdomains_string
        in_path_or_query = brand in path_and_query

        if (in_subdomain or in_path_or_query) and main_domain != brand:
            brand_keywords_count += 1

    # 13. Path Depth
    path_segments = [seg for seg in pathname.split("/") if seg]
    path_depth = len(path_segments)

    return {
        "urlLength": url_length,
        "hostnameLength": hostname_length,
        "dotCount": dot_count,
        "subdomainCount": subdomain_count,
        "hyphenCount": hyphen_count,
        "hasAtSymbol": has_at_symbol,
        "isIpAddress": is_ip_address,
        "digitRatio": digit_ratio,
        "specialCharCount": special_char_count,
        "hasPunycodeOrNonAscii": has_punycode_or_non_ascii,
        "isHttps": is_https,
        "suspiciousTld": suspicious_tld,
        "brandKeywordsCount": brand_keywords_count,
        "pathDepth": path_depth,
        "isValidUrl": 1,
        "hostname": hostname
    }
