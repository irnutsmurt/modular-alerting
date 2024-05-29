#idr_alerts.py
import requests
import json
import configparser
import os
import gzip
import shutil
import httplib2
import logging
import time
import pytz
import shutil
from pathlib import Path
from httplib2 import Http
from datetime import datetime, timedelta
from logging.handlers import TimedRotatingFileHandler
from log_handler import initialize_logging 
from send_to_google_chat import send_to_google_chat
from alert_manager import check_and_send_combined_alert, load_config

logger = logging.getLogger(__name__)

# read the configuration from config.ini file
config = configparser.ConfigParser()
config.read('config.ini')

# get the InsightIDR API key and region from the config file
insightidr_api_key = config['insightidr']['api_key']
region = config['insightidr']['region']

# get priority_levels from config
priority_levels = config['insightidr']['priority_levels'].split(',')

# set variable for sent alerts
sent_alert_rrns_file = 'sent_alert_rrns.txt'

# set the InsightIDR API endpoint URL
now = datetime.utcnow()
start_time = (now - timedelta(minutes=5)).isoformat() + 'Z'  # 5 minutes before now
end_time = now.isoformat() + 'Z'  # now

insightidr_url = f"https://{region}.api.insight.rapid7.com/idr/v2/investigations?filter=created_time>{start_time}&filter=created_time<{end_time}"
insightidr_headers = {
    'X-Api-Key': insightidr_api_key,
    'Content-Type': 'application/json',
    'Accept-version': 'investigations-preview'
}

insightidr_url_v1 = f"https://{region}.api.insight.rapid7.com/idr/v1/investigations"
insightidr_headers_v1 = {
    'X-Api-Key': insightidr_api_key,
    'Content-Type': 'application/json',
}

# set the file path and name for the JSON alert files
raw_alerts_file = 'raw_alerts.json'
formatted_alerts_file = 'formatted_alerts.json'

# define Http object
http_obj = Http()

def update_api_status(api, status, filename='idrapistatus.json', reset_time=False):
    # Load existing status
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            api_status = json.load(f)
    else:
        api_status = {}
    
    current_time = datetime.utcnow().isoformat()
    previous_status = api_status.get(api, {}).get('status', 200)
    first_encountered_time = api_status.get(api, {}).get('first_encountered_time', current_time)

    # If status code has changed to a non-200, update first encountered time
    if status != 200 and (previous_status == 200 or reset_time):
        first_encountered_time = current_time

    api_status[api] = {
        'status': status, 
        'previous_status': previous_status, 
        'first_encountered_time': first_encountered_time
    }
    with open(filename, 'w') as f:
        json.dump(api_status, f)

    return previous_status, first_encountered_time

def check_and_send_followup(api, status, first_encountered_time, duration=3600):
    if status != 200:
        time_diff = (datetime.utcnow() - datetime.fromisoformat(first_encountered_time)).total_seconds()
        if time_diff > duration:
            # Send follow-up alert
            error_message = f"InsightIDR api ({api}) has been returning '{status}' for over {duration/3600} hour(s)"
            send_alerts_to_chat({"text": error_message}, set(), set())
            logger.error(error_message)
            # Reset first encountered time to avoid repeated alerts
            update_api_status(api, status, reset_time=True)

def get_raw_alerts():
    logger.info("IDR - Fetching alerts from InsightIDR V2.")
    response = requests.get(insightidr_url, headers=insightidr_headers)
    previous_status, first_encountered_time = update_api_status('apiv2', response.status_code)
    
    if response.status_code != 200:
        check_and_send_followup('apiv2', response.status_code, first_encountered_time)
        if response.status_code != previous_status:
            error_message = f"InsightIDR api (v2) returned a '{response.status_code}', could not get alerts"
            send_alerts_to_chat({"text": error_message}, set(), set())
        logger.error(f"IDR - Failed to get investigations from InsightIDR: {response.reason}")
        return []
        
    # parse the response and return the list of investigations
    investigations = response.json()['data']
    # Filter out the alerts based on priority_levels
    investigations = [alert for alert in investigations if alert['priority'] in priority_levels]
    logger.info(f"IDR - Received {len(investigations)} investigations.")
    return investigations

def get_raw_alerts_v1():
    logger.info("IDR - Starting get_raw_alerts_v1 function.")
    response = requests.get(insightidr_url_v1, headers=insightidr_headers_v1)
    logger.debug(f"IDR - Response from InsightIDR V1 API: Status Code: {response.status_code}, Response Body: {response.text}")

    previous_status, first_encountered_time = update_api_status('apiv1', response.status_code)
    
    if response.status_code != 200:
        check_and_send_followup('apiv1', response.status_code, first_encountered_time)
        if response.status_code != previous_status:
            error_message = f"InsightIDR api (v1) returned a '{response.status_code}', could not get alerts"
            send_alerts_to_chat({"text": error_message}, set(), set())
        logger.error(f"IDR - Failed to get investigations from InsightIDR V1 API: {response.reason}")
        return []
        
    investigations_v1 = response.json()['data']
    logger.debug(f"IDR - Full Response from V1 API: {response.json()}")
    logger.info(f"IDR - Received {len(investigations_v1)} investigations from V1 API.")
    logger.debug(f"IDR - Investigations V1 Details: {investigations_v1}")
    return investigations_v1

def format_alerts(alerts, alerts_v1):
    logger.info("IDR - Formatting alerts.")
    # Log the incoming data for verification
    logger.debug(f"V2 Alerts: {alerts}")
    logger.debug(f"Received V1 Alerts: {alerts_v1}")

    message = ''
    for alert in alerts:
        priority = alert.get('priority')
        created_time = alert.get('created_time')
        title = alert.get('title')
        rrn = alert.get('rrn')

        logger.debug(f"Processing V2 Alert, RRN: {rrn}")

        matching_alert_v1 = next((a for a in alerts_v1 if a['rrn'] == rrn), None)

        # In format_alerts
        if matching_alert_v1:
            logger.debug(f"Matching V1 Alert: {matching_alert_v1}") 
            id_v1 = matching_alert_v1.get('id', '')
            logger.info(f"Found matching V1 Alert for RRN: {rrn}, ID: {id_v1}")
            url = f"https://{region}.idr.insight.rapid7.com/op/BDE0A5B9164310E49EBD#/investigations/{id_v1}"
        else:
            logger.warning(f"No matching V1 Alert found for RRN: {rrn}")
            url = ''

        message += f"*Title:* {title}\n"
        message += f"*Created Time:* {created_time}\n"
        message += f"*Priority:* {priority}\n"
        message += f"*Investigation URL:* {url}\n\n"

    data = {"text": message}
    logger.info("IDR - Finished formatting alerts.")
    return data

def save_formatted_alerts(payload):
    logger.info("IDR - Saving formatted alerts to file.")
    # save the formatted alerts to a file
    with open(formatted_alerts_file, 'w') as f:
        json.dump(payload, f, indent=4)
    logger.debug(f"IDR - {len(payload['cards'])} formatted alerts saved to {formatted_alerts_file}")

def send_alerts_to_chat(payload, alert_rrns, sent_alert_rrns):
    logger.info("IDR - Sending alerts to chat.")
    global sent_alert_rrns_file
    webhook_url = config['insightidr']['webhook_url']
    message = payload['text']  # Assuming payload is still a dictionary with a 'text' key.
    
    # Using the imported send_to_google_chat function
    send_to_google_chat(message, webhook_url)

    # add the RRNs of the sent alerts to the set of already-sent alert RRNs
    if alert_rrns and sent_alert_rrns:  # Only update if there are actual alert RRNs
        sent_alert_rrns.update(alert_rrns)
        with open(sent_alert_rrns_file, 'w') as f:
            f.writelines([rrn + '\n' for rrn in sent_alert_rrns])
    logger.info("IDR - Sent alerts to chat and updated RRNs.")

def run_idr_alerts():
    global sent_alert_rrns_file
    global raw_alerts_file

    # Ensure sent_alert_rrns.txt exists, create it if not
    if not Path(sent_alert_rrns_file).is_file():
        with open(sent_alert_rrns_file, 'w') as f:
            pass
        logger.debug(f"IDR - Created new file: {sent_alert_rrns_file}")

    # Load sent alerts RRNs
    sent_alert_rrns = set()
    with open(sent_alert_rrns_file, 'r') as f:
        sent_alert_rrns = {line.strip() for line in f}
    logger.debug("IDR - Loaded sent alert RRNs.")

    # Get the list of raw alerts from InsightIDR
    raw_alerts = get_raw_alerts()
    raw_alerts_v1 = get_raw_alerts_v1()

    if raw_alerts is None or raw_alerts_v1 is None:
        logger.warning("IDR - Failed to fetch raw alerts. Exiting function.")
        return  # Exit the function if either API call fails

    # Filter the alerts to exclude already-sent alerts
    new_alerts = [alert for alert in raw_alerts if alert['rrn'] not in sent_alert_rrns]
    logger.debug(f"IDR - {len(new_alerts)} new alerts found after filtering.")

    if new_alerts:
        logger.info(f"IDR - {len(new_alerts)} new alerts found.")

        # Format the new alerts into a payload that Google Chat can read
        formatted_payload = format_alerts(new_alerts, raw_alerts_v1)

        # Send the formatted alerts to Google Chat
        send_alerts_to_chat(formatted_payload, [alert['rrn'] for alert in new_alerts], sent_alert_rrns)

        # Update the set of sent alert RRNs
        sent_alert_rrns.update([alert['rrn'] for alert in new_alerts])
        with open(sent_alert_rrns_file, 'w') as f:
            f.writelines([rrn + '\n' for rrn in sent_alert_rrns])
        logger.info("IDR - Sent alerts to chat and updated RRNs.")

    else:
        logger.info("IDR - No new alerts found.")

    # Purge raw alerts file after processing
    with open(raw_alerts_file, 'w') as f:
        json.dump([], f, indent=4)
    logger.debug(f"IDR - Raw alerts file '{raw_alerts_file}' purged after processing.")