# This will save your result in Json file 
import json
import os

FILE_NAME = "ioc_results.json"

def load_iocs():
    if os.path.exists(FILE_NAME):
        with open(FILE_NAME, "r") as f:
            return json.load(f)
    return []

def save_iocs(new_iocs):
    existing_iocs = load_iocs()
    indicators_seen = {ioc['indicator'] for ioc in existing_iocs}
    merged = existing_iocs + [ioc for ioc in new_iocs if ioc['indicator'] not in indicators_seen]
    with open(FILE_NAME, "w") as f:
        json.dump(merged, f, indent=4)
