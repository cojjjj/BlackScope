import whois


def lookup_whois(domain):
    try:
        data = whois.whois(domain)

        return {
            "registrar": str(data.registrar) if data.registrar else None,
            "creation_date": _clean_date(data.creation_date),
            "expiration_date": _clean_date(data.expiration_date),
            "updated_date": _clean_date(data.updated_date),
            "name_servers": _clean_list(data.name_servers),
            "emails": _clean_list(data.emails),
            "organization": str(data.org) if getattr(data, "org", None) else None,
            "country": str(data.country) if data.country else None,
            "status": _clean_list(data.status),
        }

    except Exception as error:
        return {"error": str(error)}


def _clean_date(value):
    if isinstance(value, list):
        value = value[0] if value else None

    return str(value) if value else None


def _clean_list(value):
    if value is None:
        return []

    if isinstance(value, list):
        return [str(item) for item in value]

    return [str(value)]