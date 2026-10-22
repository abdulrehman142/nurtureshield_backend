"""Production URL feature extraction for NurtureShield corrected-v1.

This file contains inference-time text processing only. It never resolves,
opens, requests, or otherwise contacts a URL.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from typing import Iterable
from urllib.parse import parse_qs, urlsplit

import pandas as pd


SCHEMA_VERSION = "nurtureshield-corrected-v1"
SUSPICIOUS_TOKENS = (
    "login", "signin", "verify", "verification", "account", "secure",
    "update", "confirm", "password", "credential", "bank", "payment",
    "wallet", "recover", "support", "security", "authenticate", "webscr",
    "ebayisapi",
)
SCHEME_RE = re.compile(r"^(?:https?|ftp):\/\/", re.IGNORECASE)
HTTP_SCHEME_RE = re.compile(r"^(https?):\/\/", re.IGNORECASE)

FEATURE_NAMES = (
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "digit_count",
    "letter_count",
    "special_char_count",
    "dot_count",
    "hyphen_count",
    "underscore_count",
    "slash_count",
    "question_count",
    "equal_count",
    "at_count",
    "ampersand_count",
    "percent_count",
    "digit_ratio",
    "letter_ratio",
    "special_char_ratio",
    "subdomain_count",
    "uses_ip_address",
    "has_explicit_port",
    "has_percent_encoding",
    "has_punycode",
    "has_unicode",
    "suspicious_token_count",
    "has_suspicious_token",
    "path_depth",
    "query_parameter_count",
    "url_entropy",
    "hostname_entropy",
)


def canonicalize_url(value: object) -> str:
    """Return the exact corrected-v1 URL spelling used by the model."""
    text = str(value).strip()
    return HTTP_SCHEME_RE.sub("", text, count=1)


def _parse_url(value: object):
    text = str(value).strip()
    parse_target = text if SCHEME_RE.match(text) else "//" + text
    try:
        return urlsplit(parse_target)
    except ValueError:
        return urlsplit("//")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _is_ip(hostname: str) -> int:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return 0
    return 1


def extract_url_features(value: object) -> dict[str, float | int]:
    """Extract the finalized 31-feature representation from URL text."""
    url = canonicalize_url(value)
    parsed = _parse_url(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    url_lower = url.lower()
    url_length = len(url)
    digits = sum(char.isdigit() for char in url)
    letters = sum(char.isalpha() for char in url)
    special = sum(not char.isalnum() for char in url)
    hostname_parts = [part for part in hostname.split(".") if part]
    suspicious = sum(url_lower.count(token) for token in SUSPICIOUS_TOKENS)
    try:
        query_parameters = len(parse_qs(query, keep_blank_values=True))
    except ValueError:
        query_parameters = 0
    try:
        explicit_port = int(parsed.port is not None)
    except ValueError:
        explicit_port = 1

    return {
        "url_length": url_length,
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "digit_count": digits,
        "letter_count": letters,
        "special_char_count": special,
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "underscore_count": url.count("_"),
        "slash_count": url.count("/"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "at_count": url.count("@"),
        "ampersand_count": url.count("&"),
        "percent_count": url.count("%"),
        "digit_ratio": digits / url_length if url_length else 0.0,
        "letter_ratio": letters / url_length if url_length else 0.0,
        "special_char_ratio": special / url_length if url_length else 0.0,
        "subdomain_count": max(len(hostname_parts) - 2, 0),
        "uses_ip_address": _is_ip(hostname),
        "has_explicit_port": explicit_port,
        "has_percent_encoding": int(bool(re.search(r"%[0-9a-fA-F]{2}", url))),
        "has_punycode": int("xn--" in hostname),
        "has_unicode": int(any(ord(char) > 127 for char in url)),
        "suspicious_token_count": suspicious,
        "has_suspicious_token": int(suspicious > 0),
        "path_depth": len([segment for segment in path.split("/") if segment]),
        "query_parameter_count": query_parameters,
        "url_entropy": _entropy(url),
        "hostname_entropy": _entropy(hostname),
    }


def feature_frame(urls: Iterable[object]) -> pd.DataFrame:
    """Build model input with the exact finalized feature order."""
    return pd.DataFrame(
        [extract_url_features(url) for url in urls],
        columns=FEATURE_NAMES,
    )
