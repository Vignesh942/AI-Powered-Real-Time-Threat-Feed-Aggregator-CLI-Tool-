# check_virustotal.py
import hashlib
import base64
import requests
from config import VIRUSTOTAL_API_KEY

VT_URL = "https://www.virustotal.com/api/v3"

headers = {
    "x-apikey": VIRUSTOTAL_API_KEY
}

def vt_normalize_url(url: str) -> str:
    """Normalize and base64-encode URL for VirusTotal lookup"""
    url = url.strip()
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return url_id

def vt_hash_url(url: str) -> str:
    """SHA256 hash of URL (VT requirement for /urls endpoint)"""
    return hashlib.sha256(url.encode()).hexdigest()


def vt_check(ioc: str):
    ioc = ioc.strip()

    # ---------------------------
    # 1. URL CHECK
    # ---------------------------
    if "://" in ioc or "/" in ioc:
        try:
            # Correct VT process:
            url_id = vt_normalize_url(ioc)
            url_hash = vt_hash_url(ioc)

            # VT prefers hashed URL lookup
            vt_endpoint = f"{VT_URL}/urls/{url_hash}"

            r = requests.get(vt_endpoint, headers=headers, timeout=15)
            data = r.json()

            # If not found, fallback to encoded URL ID
            if "error" in data:
                vt_endpoint = f"{VT_URL}/urls/{url_id}"
                r = requests.get(vt_endpoint, headers=headers, timeout=15)
                data = r.json()

            if "data" not in data:
                return {"error": f"VT lookup failed", "raw": data}

            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "type": "url",
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
            }

        except Exception as e:
            return {"error": f"VT error: {str(e)}"}

    # ---------------------------
    # 2. DOMAIN CHECK
    # ---------------------------
    if "." in ioc and not ioc.replace(".", "").isdigit():
        try:
            vt_endpoint = f"{VT_URL}/domains/{ioc}"
            r = requests.get(vt_endpoint, headers=headers, timeout=15)
            data = r.json()

            if "data" not in data:
                return {"error": "Domain not found in VT", "raw": data}

            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "type": "domain",
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
            }

        except Exception as e:
            return {"error": f"VT error: {str(e)}"}

    # ---------------------------
    # 3. IP CHECK
    # ---------------------------
    if all(part.isdigit() for part in ioc.split(".")):
        try:
            vt_endpoint = f"{VT_URL}/ip_addresses/{ioc}"
            r = requests.get(vt_endpoint, headers=headers, timeout=15)
            data = r.json()

            if "data" not in data:
                return {"error": "IP not found in VT", "raw": data}

            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "type": "ip",
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
            }

        except Exception as e:
            return {"error": f"VT error: {str(e)}"}

    return {"error": "Invalid IOC format"}
