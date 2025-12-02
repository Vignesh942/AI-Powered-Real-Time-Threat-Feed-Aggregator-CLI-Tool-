import requests
from config import ALIENVAULT_API_KEY

def get_otx_ip_indicators():
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print("Error fetching OTX data:", e)
        return []

    data = response.json()
    indicators = []

    for pulse in data.get("results", []):
        for ioc in pulse.get("indicators", []):
            if ioc.get("type") == "IPv4":  # Only IPs for now
                indicators.append({
                    "indicator": ioc.get("indicator"),
                    "type": "ip",
                    "source": "OTX",
                    "threat_type": pulse.get("name", "unknown"),
                    "first_seen": ioc.get("created")
                })
    return indicators

if __name__ == "__main__":
    ips = get_otx_ip_indicators()
    print(ips[:5])
