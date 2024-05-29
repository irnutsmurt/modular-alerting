#admin_by_request.py
import requests
import json
import os
import logging
from log_handler import initialize_logging
from send_to_google_chat import json_send_to_google_chat
from configparser import ConfigParser
from datetime import datetime
from alert_manager import check_and_send_alert, load_config

# Initialize logging
logger = logging.getLogger(__name__)

# Load configuration
config = load_config()

# ABR Configuration
API_URL = config.get('ABR', 'api_url')
API_KEY = config.get('ABR', 'apikey')
WEBHOOK_URL = config.get('ABR', 'webhook_url')
SENT_ALERTS_FILE = 'abr_sent_alerts.json'

def get_events():
    logger.info("Fetching events from Admin By Request API.")
    headers = {
        'apikey': API_KEY
    }
    response = requests.get(f"{API_URL}/auditlog?days=1&status=Quarantined", headers=headers)
    status_code = response.status_code
    check_and_send_alert('ABR', status_code, config)

    if status_code == 200:
        logger.info(f"Received response: {response.json()}")
        return response.json()
    else:
        logger.info(f"Failed to fetch events: {status_code} - {response.text}")
        return []

def load_sent_alerts():
    if not os.path.exists(SENT_ALERTS_FILE):
        logger.error(f"Sent alerts file {SENT_ALERTS_FILE} does not exist. Creating a new set.")
        return set()
    with open(SENT_ALERTS_FILE, 'r') as file:
        logger.info(f"Loading sent alerts from {SENT_ALERTS_FILE}.")
        return set(json.load(file))

def save_sent_alerts(sent_alerts):
    with open(SENT_ALERTS_FILE, 'w') as file:
        logger.debug(f"Saving sent alerts to {SENT_ALERTS_FILE}.")
        json.dump(list(sent_alerts), file)

def format_alert_message(event):
    logger.info(f"Formatting alert message for event ID {event['id']}.")
    
    application = event['application']
    user = event['user']
    computer = event['computer']
    
    message = (
        f"<b>Request Time:</b> {event['requestTime']}<br>"
        f"<b>Computer Name:</b> {computer['name']}<br>"
        f"<b>Computer Platform:</b> {computer['platform']}<br>"
        f"<b>User Account:</b> {user['account']}<br>"
        f"<b>User Full Name:</b> {user['fullName']}<br>"
        f"<b>Application File:</b> {application['file']}<br>"
        f"<b>Application Path:</b> {application['path']}<br>"
        f"<b>SHA256:</b> {application['sha256']}<br>"
        f"<b>Scan Result:</b> {application['scanResult']}<br>"
        f"<b>Threat:</b> {application['threat']}<br>"
    )

    widgets = [
        {
            "textParagraph": {
                "text": message
            }
        }
    ]

    investigation_widget = {
        "textParagraph": {
            "text": f'Investigate further by clicking <a href="{event["auditlogLink"]}">HERE</a><br>'
                    f'Check the VirusTotal Report <a href="{application["virustotalLink"]}">HERE</a>'
        }
    }

    chat_message = {
        "cardsV2": [
            {
                "card": {
                    "header": {
                        "title": "Admin By Request Alert",
                        "imageUrl": "https://www.adminbyrequest.com/wp-content/uploads/2023/06/cropped-Favicon-512x512px-01.png",
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

    logger.info(f"Formatted chat message: {chat_message}")
    return json.dumps(chat_message)

def process_events(events, sent_alerts):
    logger.info("Processing events.")
    new_alerts = []
    for event in events:
        event_id = event['id']
        if event_id not in sent_alerts:
            logger.debug(f"Event ID {event_id} is new. Preparing to send alert.")
            alert_message = format_alert_message(event)
            json_send_to_google_chat(alert_message, WEBHOOK_URL)
            logger.info(f"Sent alert for event ID {event_id}")
            new_alerts.append(event_id)
        else:
            logger.error(f"Event ID {event_id} has already been sent.")
    return new_alerts

def main():
    logger.info("Fetching Admin By Request events...")
    sent_alerts = load_sent_alerts()
    events = get_events()
    if events:
        logger.debug(f"Received {len(events)} events.")
        new_alerts = process_events(events, sent_alerts)
        if new_alerts:
            logger.debug(f"New alerts to save: {new_alerts}")
            sent_alerts.update(new_alerts)
            save_sent_alerts(sent_alerts)
        else:
            logger.info("No new alerts to process.")
    else:
        logger.info("No new events found.")

if __name__ == '__main__':
    main()
