import socket
import ssl
from datetime import datetime


def check_ssl_certificate(domain):
    """
    Retrieve SSL certificate information for a domain.
    """

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:

                certificate = secure_sock.getpeercert()

                issuer = dict(x[0] for x in certificate.get("issuer", []))
                subject = dict(x[0] for x in certificate.get("subject", []))

                not_before = certificate.get("notBefore")
                not_after = certificate.get("notAfter")

                expires = datetime.strptime(
                    not_after,
                    "%b %d %H:%M:%S %Y %Z"
                )

                starts = datetime.strptime(
                    not_before,
                    "%b %d %H:%M:%S %Y %Z"
                )

                days_remaining = (expires - datetime.utcnow()).days

                return {
                    "valid": True,
                    "hostname": domain,
                    "subject": subject.get("commonName"),
                    "issuer": issuer.get("commonName"),
                    "organization": issuer.get("organizationName"),
                    "serial_number": certificate.get("serialNumber"),
                    "version": certificate.get("version"),
                    "valid_from": starts.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "valid_until": expires.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "days_remaining": days_remaining,
                }

    except Exception as error:

        return {
            "valid": False,
            "error": str(error),
        }