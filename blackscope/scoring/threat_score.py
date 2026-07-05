from datetime import datetime, timezone


def calculate_risk_score(results):
    score = 100
    findings = []
    warnings = []

    ssl_data = results.get("ssl", {})
    whois_data = results.get("whois", {})
    headers_data = results.get("headers", {})
    ip_data = results.get("ip_intel", {})

    if ssl_data.get("valid"):
        findings.append("Valid SSL Certificate")
    else:
        score -= 20
        warnings.append("Invalid or missing SSL certificate")

    if ssl_data.get("days_remaining") is not None:
        if ssl_data["days_remaining"] < 30:
            score -= 10
            warnings.append("SSL certificate expires soon")
        else:
            findings.append("SSL certificate is not near expiration")

    domain_age = get_domain_age(whois_data.get("creation_date"))

    if domain_age is not None:
        if domain_age >= 2:
            findings.append(f"Domain is {domain_age} years old")
        else:
            score -= 15
            warnings.append("Domain is newly registered")

    security_headers = headers_data.get("headers", {})

    important_headers = {
        "HSTS": 10,
        "CSP": 10,
        "X-Frame-Options": 5,
        "X-Content-Type-Options": 5,
        "Referrer-Policy": 5,
        "Permissions-Policy": 3,
        "COOP": 3,
        "CORP": 3,
        "COEP": 3,
    }

    for header, penalty in important_headers.items():
        header_info = security_headers.get(header, {})

        if header_info.get("present"):
            findings.append(f"{header} Enabled")
        else:
            score -= penalty
            warnings.append(f"{header} Missing")

    if ip_data.get("reverse_dns") and ip_data.get("reverse_dns") != "Not found":
        findings.append("Reverse DNS Present")
    else:
        score -= 5
        warnings.append("Reverse DNS Missing")

    if headers_data.get("status_code"):
        findings.append("HTTPS Enabled")

    score = max(0, min(100, score))

    if score >= 80:
        risk_level = "LOW"
    elif score >= 50:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "warnings": warnings,
    }


def get_domain_age(creation_date):
    if not creation_date:
        return None

    try:
        clean_date = creation_date.split("+")[0].strip()

        created = datetime.fromisoformat(clean_date)

        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        return max(0, now.year - created.year)

    except Exception:
        return None