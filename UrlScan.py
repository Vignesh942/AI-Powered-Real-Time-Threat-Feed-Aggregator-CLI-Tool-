import time
import requests
from config import URLSCAN_API_KEY

def urlscan_check(target):
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }

    submit_url = "https://urlscan.io/api/v1/scan/"
    payload = {"url": target, "public": "off"}

    try:
        # Submit URL for scanning
        submit_res = requests.post(submit_url, json=payload, headers=headers)
        submit_data = submit_res.json()
        uuid = submit_data.get("uuid")

        if not uuid:
            return {"error": f"Scan submission failed: {submit_data}"}

        result_url = f"https://urlscan.io/api/v1/result/{uuid}/"

        # Wait for result
        timeout = 60
        interval = 5
        waited = 0
        result_data = None

        while waited < timeout:
            res = requests.get(result_url)
            if res.status_code == 200:
                result_data = res.json()
                break
            time.sleep(interval)
            waited += interval

        if not result_data:
            return {"error": "Result not ready in time"}

        # Normalize fields
        normalized = {
            "url": result_data.get("page", {}).get("url"),
            "tags": result_data.get("page", {}).get("tags"),
            "verdict": result_data.get("verdicts", {}).get("overall"),
            "malicious": result_data.get("verdicts", {}).get("malicious"),
            "suspicious": result_data.get("verdicts", {}).get("suspicious"),
            "harmless": result_data.get("verdicts", {}).get("harmless")
        }

        return normalized

    except Exception as e:
        return {"error": str(e)}
