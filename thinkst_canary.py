import requests
import logging
import json
import os
from configparser import ConfigParser
from send_to_google_chat import json_send_to_google_chat
from datetime import datetime, timedelta
from pytz import timezone
from log_handler import initialize_logging
from send_to_google_chat import send_to_google_chat
from alert_manager import check_and_send_alert, load_config

# Initialize logging
logger = logging.getLogger(__name__)

# Read configuration
config = ConfigParser()
config.read('config.ini')

# Thinkst Canary Configuration
canary_auth_token = config['thinkst_canary']['auth_token']
canary_webhook_url = config['thinkst_canary']['webhook_url']
canary_limit = config['thinkst_canary'].get('limit', '1')
canary_id = config['thinkst_canary']['canary_id']

# Path to the file storing sent alert hash IDs
sent_alerts_file = 'canary_alert_hash_sent.json'

# Ensure the sent_alerts_file exists
if not os.path.exists(sent_alerts_file):
    with open(sent_alerts_file, 'w') as f:
        json.dump([], f)
    logger.info(f"Created file: {sent_alerts_file}")

# Load sent alert hash IDs from file
with open(sent_alerts_file, 'r') as f:
    sent_alert_hashes = set(json.load(f))
logger.info(f"Loaded {len(sent_alert_hashes)} hash IDs from {sent_alerts_file}")

def fetch_thinkst_canary_alerts():
    url = f'https://{canary_id}.canary.tools/api/v1/incidents/search'
    payload = {
        'auth_token': canary_auth_token,
        'limit': canary_limit
    }

    try:
        response = requests.get(url, params=payload)
        logger.debug(f"Full Response from Thinkst Canary API: {response.json()}")
        status_code = response.status_code

        check_and_send_alert('thinkst_canary', status_code, load_config())
        
        if status_code == 200:
            incidents = response.json()
            logger.info(f"Received {len(incidents['incidents'])} incidents from Thinkst Canary API.")
            process_and_send_alerts(incidents)
        else:
            logger.warning(f"Received non-200 status code: {status_code}")

    except requests.RequestException as e:
        logger.error(f"Error fetching Thinkst Canary alerts: {e}")
        check_and_send_alert('thinkst_canary', 500, load_config())

def process_and_send_alerts(incidents):
    new_alerts = []

    for incident in incidents['incidents']:
        hash_id = incident['hash_id']
        if hash_id not in sent_alert_hashes:
            logger.debug(f"New incident with hash ID: {hash_id}")
            message = format_alert_message(incident)
            json_send_to_google_chat(message, canary_webhook_url)
            sent_alert_hashes.add(hash_id)
            new_alerts.append(hash_id)
        else:
            logger.debug(f"Incident with hash ID: {hash_id} has already been processed.")

    # Update the JSON file with new alert hash IDs
    if new_alerts:
        with open(sent_alerts_file, 'w') as f:
            json.dump(list(sent_alert_hashes), f)
        logger.info(f"Updated {sent_alerts_file} with {len(new_alerts)} new hash IDs.")

def format_alert_message(incident):
    description = incident['description']
    logger.debug(f"Formatting message for incident: {incident['hash_id']}")

    # Convert Unix timestamp to PT
    utc_time = datetime.utcfromtimestamp(int(incident['created']))
    pt_time = utc_time.astimezone(timezone('America/Los_Angeles'))
    pt_time_str = pt_time.strftime('%Y-%m-%d %H:%M:%S %Z%z')

    investigation_url = f"https://{canary_id}.canary.tools/nest/incident/{incident['hash_id']}"

    # General info
    message = f"<b>Timestamp (PT):</b> {pt_time_str}<br>"

    # Destination and Source Info
    host_port_group = (
        f"<b>Destination Host:</b> {incident['dst_host']}<br>"
        f"<b>Destination Port:</b> {incident['dst_port']}<br>"
        f"<b>Source Host:</b> {incident['src_host']}<br>"
        f"<b>Source Port:</b> {incident['src_port']}<br>"
    )

    # Widgets for common fields
    widgets = [
        {
            "textParagraph": {
                "text": message
            }
        },
        {
            "textParagraph": {
                "text": host_port_group
            }
        }
    ]

    # Add Canarytoken triggered information
    if description == "Canarytoken triggered" and 'logdata' in incident and incident['logdata']:
        event = incident['logdata'][0]
        additional_info = event.get('additional_info', {})
        our_email = additional_info.get('our_email', 'N/A')
        their_email = additional_info.get('their_email', 'N/A')
        event_type = event.get('type', 'N/A')
        canarytoken_info = (
            f"<b>Event Type:</b> {event_type}<br>"
            f"<b>Our Email:</b> {our_email}<br>"
            f"<b>Their Email:</b> {their_email}<br>"
        )
        widgets.append({
            "textParagraph": {
                "text": canarytoken_info
            }
        })

    # Add Console Settings Changed information
    if description == "Console Settings Changed":
        events_count = incident.get('events_count', '0')
        console_settings_info = (
            f"<b>Settings Changed Count:</b> {events_count}<br>"
        )
        widgets.append({
            "textParagraph": {
                "text": console_settings_info
            }
        })
        for index, setting_event in enumerate(incident.get('logdata', []), start=1):
            setting_change = setting_event.get('SETTINGS', 'N/A')
            widgets.append({
                "textParagraph": {
                    "text": f"<b>Settings {index} Changed:</b> {setting_change}<br>"
                }
            })

    # Add the investigation link as the last widget
    investigation_widget = {
        "textParagraph": {
            "text": f'Investigate further by clicking <a href="{investigation_url}">HERE</a>'
        }
    }

    # Create Google Chat message JSON
    chat_message = {
        "cardsV2": [
            {
                "card": {
                    "header": {
                        "title": description,
                        "imageUrl": "https://pbs.twimg.com/profile_images/1494356007480397830/7AFbX7_7_400x400.png",
                        "imageType": "CIRCLE"
                    },
                    "sections": [
                        {
                            "widgets": widgets
                        },
                        {
                            "widgets": [investigation_widget]
                        }
                    ]
                }
            }
        ]
    }

    return json.dumps(chat_message)

if __name__ == "__main__":
    fetch_thinkst_canary_alerts()
