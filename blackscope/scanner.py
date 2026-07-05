import socket
import time

from blackscope.intelligence.dns_lookup import lookup_dns
from blackscope.intelligence.headers import analyze_headers
from blackscope.intelligence.ip_lookup import lookup_ip
from blackscope.intelligence.ssl_checker import check_ssl_certificate
from blackscope.intelligence.tech_detector import detect_technologies
from blackscope.intelligence.whois_lookup import lookup_whois
from blackscope.scoring.threat_score import calculate_risk_score


def scan_target(target):
    start_time = time.time()

    results = {
        "target": target,
        "ip_address": None,
        "dns": {},
        "whois": {},
        "ssl": {},
        "headers": {},
        "ip_intel": {},
        "technologies": {},
        "risk_assessment": {},
        "scan_duration": None,
        "status": "unknown",
        "errors": [],
    }

    try:
        ip_address = socket.gethostbyname(target)

        results["ip_address"] = ip_address
        results["status"] = "resolved"

        results["dns"] = lookup_dns(target)
        results["whois"] = lookup_whois(target)
        results["ssl"] = check_ssl_certificate(target)
        results["headers"] = analyze_headers(target)
        results["ip_intel"] = lookup_ip(ip_address)
        results["technologies"] = detect_technologies(target)

        results["risk_assessment"] = calculate_risk_score(results)

    except Exception as error:
        results["errors"].append(str(error))
        results["status"] = "failed"

    finally:
        results["scan_duration"] = round(time.time() - start_time, 2)

    return results