import requests
from flask import Blueprint, render_template
import os

feed_bp = Blueprint('feed', __name__,  static_folder='../static', template_folder='../templates')



@feed_bp.route('/feed')
def feed():

    MISP_API_KEY = os.getenv('MISP_API_KEY')
    MISP_URL = os.getenv('MISP_URL')
    MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'
    headers = {
        'Authorization': MISP_API_KEY,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    url = f"{MISP_URL}/events/index"

    params = {
        'limit': 15,
        'order': 'desc'
    }

    try:
        response = requests.get(url, headers=headers, params=params, verify=MISP_VERIFY_SSL)
        response.raise_for_status()  # Check for HTTP errors

        events = response.json()  # Parse JSON response

        event_data = [
                         {
                             "id": event["id"],
                             "info": event["info"],
                             "date": event["date"],
                             "threat_level": event["threat_level_id"],
                             "organization": event.get("Orgc", {}).get("name", "Unknown")
                         }
                         for event in events
                     ][::-1]  # Rverse the list to ascending order
    except requests.exceptions.RequestException as e:
        print(f"Error fetching events: {e}")
        event_data = []

    return render_template('feed.html', events=event_data)


