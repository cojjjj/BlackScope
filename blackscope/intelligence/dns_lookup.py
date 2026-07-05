import dns.resolver


def lookup_dns(domain):
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(answer) for answer in answers]
        except Exception:
            records[record_type] = []

    return records