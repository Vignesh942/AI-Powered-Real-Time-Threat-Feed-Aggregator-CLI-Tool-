import whois as whois_module

def get_whois(domain):
    try:
        info = whois_module.whois(domain)
        return {
            "domain": info.domain_name if info.domain_name else domain,
            "registrar": info.registrar,
            "creation_date": str(info.creation_date),
            "expiration_date": str(info.expiration_date),
            "status": info.status,
            "emails": info.emails,
            "name_servers": info.name_servers
        }
    except Exception as e:
        return {"error": str(e)}
