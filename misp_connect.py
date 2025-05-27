import os
import json

# Get the directory of this file (misp_connect.py)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MISP_API_KEYS_FILE = os.path.join(BASE_DIR, 'misp_keys.json')  # Ensures correct path

# Load API Keys Once into Memory
API_KEYS = {}
if os.path.exists(MISP_API_KEYS_FILE):
    try:
        with open(MISP_API_KEYS_FILE, 'r') as f:
            API_KEYS = json.load(f)
    except Exception as e:
        print(f"Error loading API keys: {e}")
else:
    print(f"Warning: misp_keys.json not found at {MISP_API_KEYS_FILE}")

def get_api_key_for_org(organisation_name):
    """Retrieve the API key for the selected organisation."""
    return API_KEYS.get(organisation_name)

def get_available_organisations():
    """Retrieve a list of available organisations."""
    return list(API_KEYS.keys())
