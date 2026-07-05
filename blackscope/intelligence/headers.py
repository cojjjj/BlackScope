import requests


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "COOP",
    "cross-origin-resource-policy": "CORP",
    "cross-origin-embedder-policy": "COEP",
}


def analyze_headers(domain):
    try:
        response = requests.get(
            f"https://{domain}",
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "BlackScope/1.0"
                )
            },
        )

        # Convert all response headers to lowercase
        headers = {k.lower(): v for k, v in response.headers.items()}

        results = {}

        for real_name, display_name in SECURITY_HEADERS.items():
            if real_name in headers:
                results[display_name] = {
                    "present": True,
                    "value": headers[real_name],
                }
            else:
                results[display_name] = {
                    "present": False,
                    "value": None,
                }

        return {
            "status_code": response.status_code,
            "server": headers.get("server", "Unknown"),
            "powered_by": headers.get("x-powered-by", "Unknown"),
            "headers": results,
        }

    except Exception as error:
        return {"error": str(error)}