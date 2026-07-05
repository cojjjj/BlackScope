import socket

from ipwhois import IPWhois


def lookup_ip(ip_address):
    try:
        try:
            reverse_dns = socket.gethostbyaddr(ip_address)[0]
        except Exception:
            reverse_dns = "Not found"

        obj = IPWhois(ip_address)
        data = obj.lookup_rdap(depth=1)

        network = data.get("network", {})

        return {
            "ip": ip_address,
            "reverse_dns": reverse_dns,
            "asn": data.get("asn"),
            "asn_cidr": data.get("asn_cidr"),
            "asn_country": data.get("asn_country_code"),
            "asn_description": data.get("asn_description"),
            "network_name": network.get("name"),
            "network_handle": network.get("handle"),
            "network_type": network.get("type"),
            "network_country": network.get("country"),
            "network_start": network.get("start_address"),
            "network_end": network.get("end_address"),
        }

    except Exception as error:
        return {"error": str(error)}