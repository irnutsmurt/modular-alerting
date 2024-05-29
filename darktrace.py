#darktrace.py
from log_handler import initialize_logging
import json
import os
import requests
import logging
import configparser
import urllib3
import hmac
import hashlib
import time
import httplib2
from datetime import datetime, timedelta, timezone
from send_to_google_chat import send_to_google_chat
from alert_manager import check_and_send_alert, load_config

logger = logging.getLogger(__name__)

# Configuration
config = configparser.ConfigParser()
config.read('config.ini')
private_token = config['darktrace']['private_token']
public_token = config['darktrace']['public_token']
url = config['darktrace']['url']
min_score = float(config['darktrace']['min_score'])
time_frame = int(config['darktrace']['time_frame'])
webhook_url = config['darktrace']['webhook_url']
raw_alerts_file = config['darktrace']['raw_alerts_file']
parsed_alerts_file = config['darktrace']['parsed_alerts_file']
sent_alerts_file = config['darktrace']['sent_alerts_file']

# Initialize http_obj
http_obj = httplib2.Http()

def load_sent_alerts(sent_alerts_file):
    logger.debug(f"Loading sent alerts from {sent_alerts_file}...")
    try:
        if os.path.exists(sent_alerts_file) and os.stat(sent_alerts_file).st_size > 0:
            with open(sent_alerts_file, 'r') as f:
                sent_alerts = json.load(f)
            logger.debug(f"Loaded {len(sent_alerts)} sent alerts from {sent_alerts_file}.")                
        else:
            with open(sent_alerts_file, 'w') as f:
                f.write("[]")
            sent_alerts = []
            logger.info(f"{sent_alerts_file} is empty or doesn't exist. Initialized with an empty list.")            
    except (json.JSONDecodeError, TypeError) as e:
        logger.error(f"Failed to load sent alerts from {sent_alerts_file}: {str(e)}")
        sent_alerts = []

    if not isinstance(sent_alerts, list):
        logger.error(f"Invalid data format in {sent_alerts_file}. Expected a list.")
        return set()

    return set(alert['pbid'] for alert in sent_alerts if 'pbid' in alert)

def format_alert_for_google_chat(alert):
    # Define the base URL for the investigation link
    url = f'https://sc-darktrace/#modelbreach/{alert["pbid"]}'

    formatted_message = ""
    # Process each field except "Description" for special handling
    fields = [
        ("Alert", "name"),
        ("Score", "score"),
        ("Source Hostname", "device"),
        ("Source IP", "ip"),
        ("Destination Hostname", "destination_hostname"),
        ("Destination IP", "destination_ip"),
        ("Category", "category"),
        ("Time", "time"),
    ]
    for field_name, key in fields:
        if key in alert and alert[key]:
            formatted_message += f"*{field_name}:* {alert[key]}\n"

    # Special processing for "Description" to handle "Action:"
    description = alert.get("description", "")
    if "Action:" in description:
        # Split description into parts before and after "Action:"
        pre_action, post_action = description.split("Action:", 1)

        # Remove extra newline before "Action:" and format action
        pre_action = pre_action.strip() + "\n"
        post_action = f"*Action:* {post_action.strip()}"  # Double asterisk for bolding

        # Join both parts with a single newline
        formatted_message += f"*Description:* {pre_action}{post_action}\n"
    else:
        # No "Action:" found, format description normally
        formatted_message += f"*Description:* {description}\n"

    # Append the investigation URL
    formatted_message += f"*Investigation URL:* {url}"

    return formatted_message

def send_alerts_to_chat(webhook_url, sent_alerts_file, parsed_alerts_file, payload=None):
    if payload:
        send_to_google_chat(payload['text'], webhook_url)
        logger.info("Darktrace - Sent custom alert to chat.")
        return
    logger.info("Darktrace - Starting to send alerts to chat...")

    # Load sent and parsed alerts
    sent_alerts = load_sent_alerts(sent_alerts_file)
    logger.debug(f"Loaded {len(sent_alerts)} sent alerts.")
    
    parsed_alerts = load_parsed_alerts(parsed_alerts_file)
    logger.debug(f"Loaded {len(parsed_alerts)} parsed alerts.")

    # Filter for new alerts based on pbid
    new_alerts = [alert for alert in parsed_alerts if 'pbid' in alert and alert['pbid'] not in sent_alerts]
    logger.info(f"Found {len(new_alerts)} new alerts to send.")

    if new_alerts:
        for alert in new_alerts:
            formatted_message = format_alert_for_google_chat(alert)
            
            # Using send_to_google_chat function to handle message sending
            send_to_google_chat(formatted_message, webhook_url)
            logger.info(f"Sent alert with pbid {alert['pbid']} to chat.")
            
            # Assuming success, you can add the 'pbid' to sent_alerts
            sent_alerts.add(alert['pbid'])
            
        # Only write to file if there are new alerts
        update_sent_alerts(sent_alerts, sent_alerts_file)
        logger.info("Darktrace - Updated sent alerts file.")
    else:
        logger.info("Darktrace - No new alerts to send")

def save_formatted_alerts(alerts, filepath):
    logger.info("Darktrace - Starting to save formatted alerts...")
    formatted_alerts = ''
    for alert in alerts:
        formatted_alerts += f'{alert["time"]} - {alert["name"]}: {alert["description"]}\n'
    
    with open(filepath, 'a') as f:
        f.write(formatted_alerts)

    logger.debug(f'Formatted alerts saved to {filepath}')

def update_sent_alerts(sent_alerts, sent_alerts_file):
    logger.info("Darktrace - Updating sent alerts file...")
    with open(sent_alerts_file, 'w') as f:
        json.dump([{"pbid": pbid} for pbid in sent_alerts], f, indent=4)
    logger.debug("Sent alerts file updated.")

def get_raw_alerts():
    logger.debug("Fetching raw alerts...")
    # Calculate the start time for the API request
    now = datetime.now(timezone.utc)
    start_time = (now - timedelta(seconds=time_frame)).timestamp() * 1000

    # Calculate the signature for model breaches
    date = datetime.utcnow().strftime('%Y%m%dT%H%M%S')
    api_request = f'/modelbreaches?starttime={start_time}&minscore={min_score}'
    signature = hmac.new(private_token.encode('ascii'),
                         (api_request + '\n' + public_token + '\n' + date).encode('ascii'),
                         hashlib.sha1).hexdigest()

    headers = {
        'DTAPI-Token': public_token,
        'DTAPI-Date': date,
        'DTAPI-Signature': signature
    }

    urllib3.disable_warnings()
    response = requests.get(url + api_request, headers=headers, verify=False)
    check_and_send_alert('darktrace', response.status_code, load_config())
    
    if response.status_code != 200:
        logger.error(f"Failed to get raw alerts from Darktrace: {response.text}")
        return None

    # save the raw alerts to a file
    with open(config['darktrace']['raw_alerts_file'], 'w') as f:
        json.dump(response.json(), f, indent=4)
    logger.debug(f"{len(response.json())} raw alerts downloaded to {config['darktrace']['raw_alerts_file']}")

    return response.json()

def load_parsed_alerts(file_path):
    logger.info("Darktrace - Loading parsed alerts...")
    if not os.path.exists(file_path):
        logger.info("Darktrace - Parsed alerts file doesn't exist. Returning an empty list.")
        return []
    with open(file_path, 'r') as f:
        data = json.load(f)
    logger.debug(f"{len(data)} parsed alerts loaded.")
    return data

def parse_raw_alerts(raw_alerts, parsed_alerts_file):
    logger.info("Darktrace - Parsing raw alerts...")

    alerts = []

    for alert in raw_alerts:
        time = datetime.fromtimestamp(alert['time'] / 1000).strftime('%Y-%m-%d %H:%M:%S')
        pbid = alert['pbid']
        score = round(alert['score'] * 100)  # convert score to percentage and round it
        name = alert['model']['now']['name']
        device = alert.get('device', {}).get('hostname', '')
        ip = alert.get('device', {}).get('ip', '')  # Extract IP address
        description = alert['model']['now']['description']
        category = alert['model'].get('then', {}).get('category', '')

        # Initialize variables for destination hostname and IP
        destination_hostname = ""
        destination_ip = ""

        # Search through triggeredFilters for destination hostname and IP
        for filter in alert.get('triggeredComponents', [])[0].get('triggeredFilters', []):
            if filter.get('filterType') == 'Connection hostname':
                destination_hostname = filter.get('trigger', {}).get('value', '')
            elif filter.get('filterType') == 'Destination IP':
                destination_ip = filter.get('trigger', {}).get('value', '')

        alerts.append({
            'time': time,
            'pbid': pbid,
            'score': str(score) + '%',
            'name': name,
            'device': device,
            'ip': ip,
            'destination_hostname': destination_hostname,  # Add destination hostname
            'destination_ip': destination_ip,  # Add destination IP
            'description': description,
            'category': category
        })

    # Display the formatted alerts
    for alert in alerts:
        logger.info(alert)  # Log the alert

    # Write the parsed alerts to file
    write_parsed_alerts(alerts, parsed_alerts_file)

    return alerts

def write_parsed_alerts(alerts, file_path):
    logger.info("Darktrace - Writing parsed alerts to file...")

    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            json.dump([], f)  # initialize with an empty list

    with open(file_path, 'w') as f:
        json.dump(alerts, f, indent=4)
        logger.debug(f"Parsed alerts written to {file_path}.")

def run_darktrace():
    logger.info("Darktrace - Fetching alerts from Darktrace...")
    # get the list of raw alerts from Darktrace
    raw_alerts = get_raw_alerts()
    
    if raw_alerts is not None:
        logger.debug(f"Received {len(raw_alerts)} raw alerts from Darktrace.")
        
        # Load the set of previously sent alerts
        sent_alerts = load_sent_alerts(sent_alerts_file)
        logger.debug(f"Loaded {len(sent_alerts)} previously sent alerts.")

        # Filter out raw alerts that have already been sent
        new_raw_alerts = [alert for alert in raw_alerts if alert['pbid'] not in sent_alerts]

        if new_raw_alerts:
            logger.info(f"{len(new_raw_alerts)} raw alerts to parse and send.")
            
            logger.info("Darktrace - Parsing raw alerts...")
            # parse the new raw alerts and save to file
            parsed_alerts = parse_raw_alerts(new_raw_alerts, parsed_alerts_file)

            # send new alerts to Google Chat
            if parsed_alerts:
                logger.info(f"Sending {len(parsed_alerts)} new alerts to Google Chat.")
                send_alerts_to_chat(webhook_url, sent_alerts_file, parsed_alerts_file)
                logger.info(f"{len(parsed_alerts)} alerts sent to Google Chat")

                # write parsed alerts to file
                write_parsed_alerts(parsed_alerts, parsed_alerts_file)
                logger.debug("Written parsed alerts to file.")

        else:
            logger.info("Darktrace - No new alerts.")
