"""Descriptive indicators copied verbatim from NurtureShield_ER.ipynb, cell 15."""
def explain_url_features(row):
    reasons = []

    # Host structure
    if row["uses_ip_address"] == 1:
        reasons.append(
            "Uses an IP address instead of a normal domain name"
        )

    if row["subdomain_count"] >= 3:
        reasons.append(
            "Contains an unusually deep subdomain structure"
        )

    if row["hostname_length"] >= 40:
        reasons.append(
            "Uses a relatively long hostname"
        )

    # Path structure
    if row["path_depth"] >= 4:
        reasons.append(
            "Contains a deeply nested URL path"
        )

    if row["path_length"] >= 75:
        reasons.append(
            "Contains a long URL path"
        )

    if row["slash_count"] >= 6:
        reasons.append(
            "Contains many path separators"
        )

    # Suspicious lexical properties
    if row["has_suspicious_token"] == 1:
        reasons.append(
            "Contains security-sensitive or suspicious terms"
        )

    if row["suspicious_token_count"] >= 2:
        reasons.append(
            "Contains multiple suspicious terms"
        )

    # Encoding / obfuscation
    if row["has_percent_encoding"] == 1:
        reasons.append(
            "Contains percent-encoded characters"
        )

    if row["has_punycode"] == 1:
        reasons.append(
            "Uses Punycode in the hostname"
        )

    if row["has_unicode"] == 1:
        reasons.append(
            "Contains Unicode characters"
        )

    # Other structural properties
    if row["has_explicit_port"] == 1:
        reasons.append(
            "Specifies an explicit network port"
        )

    if row["query_parameter_count"] >= 4:
        reasons.append(
            "Contains many query parameters"
        )

    if row["url_length"] >= 100:
        reasons.append(
            "URL is unusually long"
        )

    if row["digit_ratio"] >= 0.20:
        reasons.append(
            "Contains a high proportion of digits"
        )

    if row["special_char_ratio"] >= 0.30:
        reasons.append(
            "Contains a high proportion of special characters"
        )

    return reasons
