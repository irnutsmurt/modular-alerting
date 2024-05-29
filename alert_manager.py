import os
import json
import configparser
from datetime import datetime, timedelta
import requests
import logging
from log_handler import initialize_logging
from send_to_google_chat import send_to_google_chat

# Initialize logging
logger = logging.getLogger(__name__)

CONFIG_FILE = 'config.ini'
STATUS_FILE = 'alert_api_status.json'

def load_config():
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    logger.debug("Loaded configuration file")
    return config

def initialize_status_file(config):
    api_status = {}
    for script in config['main_scripts']['scripts'].split(', '):
        api_status[script] = {
            'status': 200,
            'previous_status': 200,
            'time': datetime.now().isoformat(),
            'previous_time': datetime.now().isoformat(),
            'alerts_after_none_200': int(config[script].get('alerts_after_none_200', 2)),
            'consecutive_failures': 0
        }
    with open(STATUS_FILE, 'w') as f:
        json.dump(api_status, f)
    logger.info(f"Initialized status file with scripts: {list(api_status.keys())}")

def update_status_file(config):
    if os.path.exists(STATUS_FILE):
        with open(STATUS_FILE, 'r') as f:
            api_status = json.load(f)
    else:
        api_status = {}
        initialize_status_file(config)
    
    current_scripts = set(config['main_scripts']['scripts'].split(', '))
    existing_scripts = set(api_status.keys())
    
    # Add new scripts
    for script in current_scripts - existing_scripts:
        api_status[script] = {
            'status': 200,
            'previous_status': 200,
            'time': datetime.now().isoformat(),
            'previous_time': datetime.now().isoformat(),
            'alerts_after_none_200': int(config[script].get('alerts_after_none_200', 2)),
            'consecutive_failures': 0
        }
        logger.info(f"Added new script to status file: {script}")
    
    # Remove scripts no longer in config
    for script in existing_scripts - current_scripts:
        del api_status[script]
        logger.info(f"Removed script from status file: {script}")
    
    with open(STATUS_FILE, 'w') as f:
        json.dump(api_status, f)
        logger.debug("Updated status file")

def update_api_status(api, status, config):
    if not os.path.exists(STATUS_FILE):
        initialize_status_file(config)
        
    with open(STATUS_FILE, 'r') as f:
        api_status = json.load(f)

    previous_status = api_status.get(api, {}).get('status', 200)
    previous_time = api_status.get(api, {}).get('time', datetime.now().isoformat())
    consecutive_failures = api_status.get(api, {}).get('consecutive_failures', 0)
    
    if status == 200:
        consecutive_failures = 0
        logger.info(f"{api} returned status code 200 OK")
    else:
        consecutive_failures += 1
        logger.error(f"{api} returned status code {status}")

    api_status[api] = {
        'status': status,
        'previous_status': previous_status,
        'time': datetime.now().isoformat(),
        'previous_time': previous_time,
        'alerts_after_none_200': int(config[api].get('alerts_after_none_200', 2)),
        'consecutive_failures': consecutive_failures
    }

    with open(STATUS_FILE, 'w') as f:
        json.dump(api_status, f)
        logger.debug(f"Updated API status for {api}: {api_status[api]}")

    return api_status[api]

def check_and_send_alert(api, status, config):
    api_status = update_api_status(api, status, config)
    webhook_url = config[api]['webhook_url']
    consecutive_failures = api_status['consecutive_failures']
    alerts_after_none_200 = api_status['alerts_after_none_200']

    if consecutive_failures >= alerts_after_none_200:
        message = f"{api} has returned status code {status}. Please check."
        send_to_google_chat(message, webhook_url)
        logger.info(f"Sent alert: {message}")
    
    if status != 200:
        previous_time_dt = datetime.fromisoformat(api_status['previous_time'])
        current_time_dt = datetime.now()
        duration = current_time_dt - previous_time_dt
        
        if duration.total_seconds() > 3600:
            message = f"{api} has returned status code {status} for over an hour. Please check."
            send_to_google_chat(message, webhook_url)
            logger.info(f"Sent alert: {message}")

def check_and_send_combined_alert(api_v1, status_v1, api_v2, status_v2, config):
    if not os.path.exists(STATUS_FILE):
        initialize_status_file(config)
        
    with open(STATUS_FILE, 'r') as f:
        api_status = json.load(f)

    current_time = datetime.now().isoformat()
    apis = [api_v1, api_v2]
    statuses = [status_v1, status_v2]
    consecutive_failures = 0

    for api, status in zip(apis, statuses):
        if api not in api_status:
            api_status[api] = {
                'status': 200,
                'previous_status': 200,
                'time': current_time,
                'previous_time': current_time,
                'alerts_after_none_200': int(config['insightidr'].get('alerts_after_none_200', 2)),
                'consecutive_failures': 0
            }

        previous_status = api_status[api]['status']
        if status == 200:
            api_status[api]['consecutive_failures'] = 0
        else:
            if previous_status == 200:
                api_status[api]['consecutive_failures'] = 1
            else:
                api_status[api]['consecutive_failures'] += 1

        consecutive_failures += api_status[api]['consecutive_failures']

        api_status[api].update({
            'status': status,
            'previous_status': previous_status,
            'time': current_time,
            'previous_time': api_status[api]['time'],
        })

    with open(STATUS_FILE, 'w') as f:
        json.dump(api_status, f)

    combined_status = max(statuses)
    alerts_after_none_200 = int(config['insightidr'].get('alerts_after_none_200', 2))

    if combined_status != 200 and consecutive_failures >= alerts_after_none_200:
        message = f"{api_v1} API returned status code {status_v1}, {api_v2} API returned status code {status_v2}. Please check."
        webhook_url = config['insightidr']['webhook_url']
        send_to_google_chat(message, webhook_url)
        logger.info(f"Sent combined alert: {message}")

if __name__ == "__main__":
    config = load_config()
    initialize_status_file(config)
    update_status_file(config)
