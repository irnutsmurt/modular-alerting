#cycognito.py
import requests
import json
import time
import os
import logging
from configparser import ConfigParser
from log_handler import initialize_logging 
from alert_manager import check_and_send_alert, load_config

logger = logging.getLogger(__name__)

# Read configurations
def read_config():
    logger.info('Cycognito - Reading configuration')
    config = ConfigParser()
    config.read('config.ini')
    api_key = config.get('Cycognito', 'api_key')
    severity_score = int(config.get('Cycognito', 'severity_score'))
    webhook_url = config.get('Cycognito', 'webhook_url')
    loop_time_seconds = int(config.get('Cycognito', 'loop_time_seconds'))
    return api_key, severity_score, webhook_url, loop_time_seconds

def read_alert_ids():
    if not os.path.exists('sent_alert_ids.txt'):
        open('sent_alert_ids.txt', 'w').close()
        return set()
    
    with open('sent_alert_ids.txt', 'r') as f:
        return set(f.read().splitlines())

def store_alert_id(alert_id):
    with open('sent_alert_ids.txt', 'a') as f:
        f.write(f"{alert_id}\n")

def get_cycognito_issues(api_key):
    logger.info('Cycognito - Polling API for new issues')
    url = "https://api.us-platform.cycognito.com/v1/issues?count=5&offset=0&fields=id%2C%20severity_score%2C%20exploitation_complexity%2C%20affected_asset%2C%20mitre_attack_technique_name%2C%20port%2C%20title%2C%20cve_ids%2C%20url%2C%20name%2C%20version%2C%20vulnerabilities%2C%20validation-guide%2C%20validation-code%2C%20remediation_steps%2C%20confidence%2C%20first_detected&sort-order=asc"
    headers = {
        "accept": "application/json",
        "Authorization": api_key,
        "Content-Type": "application/json"
    }
    payload = json.dumps([{"op": "in", "field": "status", "values": ["new"]}])
    
    response = requests.post(url, headers=headers, data=payload)
    check_and_send_alert('Cycognito', response.status_code, load_config())
    
    if response.status_code != 200:
        logger.error(f'Cycognito - API error with status code {response.status_code}')
        return None
        
    return response.json()

def filter_severity_and_new(issues, min_severity, alerted_ids):
    filtered_issues = [
        issue for issue in issues
        if issue.get('severity_score', 0) >= min_severity and issue.get('id') not in alerted_ids
    ]
    return filtered_issues

def format_for_gchat(issues):
    logger.info('Cycognito - Formatting messages for Google Chat')
    messages = []
    for issue in issues:
        message = (
            f"*Title:* {issue['title']},\n"
            f"*cve_ids:* {issue['cve_ids']},\n"
            f"*severity_score:* {issue['severity_score']},\n"
            f"*exploitation_complexity:* {issue['exploitation_complexity']},\n"
            f"*affected_asset:* {issue['affected_asset']},\n"
            f"*port:* {issue['port']},\n"
            f"*confidence:* {issue['confidence']},\n"
            f"*first_detected:* {issue['first_detected']},\n"
            f"*mitre_attack_technique_name:* {issue['mitre_attack_technique_name']},\n"
            f"*remediation_steps:* {issue['remediation_steps']}\n"
            f"*Investigation URL:* https://us-platform.cycognito.com/issues/{issue['id']}/info\n"
        )
        messages.append(message)
    return "\n".join(messages)

def send_to_google_chat(message, webhook_url):
    logger.info('Cycognito - Sending message to Google Chat')
    response = requests.post(webhook_url, json={"text": message})
    if response.status_code != 200:
        logger.error(f'Cycognito - Webhook error with status code {response.status_code}')
    else:
        logger.info('Cycognito - Message sent successfully')

def run_cycognito():
    api_key, severity_score, webhook_url, loop_time_seconds = read_config()

    logger.info('Cycognito - Checking and storing sent_alert_ids in memory')
    alerted_ids = read_alert_ids()
    cycognito_issues = get_cycognito_issues(api_key)

    if cycognito_issues is not None:
        new_severe_issues = filter_severity_and_new(cycognito_issues, severity_score, alerted_ids)

        if new_severe_issues:
            logger.info('Cycognito - New alerts found meeting the severity threshold')
            for issue in new_severe_issues:
                store_alert_id(issue['id'])
                
            message = format_for_gchat(new_severe_issues)
            send_to_google_chat(message, webhook_url) 
        else:
            logger.info('Cycognito - No new alerts found meeting the severity threshold')
    else:
        logger.error('Cycognito - API call unsuccessful, skipping this iteration')

if __name__ == '__main__':
    while True:
        run_cycognito()
        time.sleep(read_config()[3])  # Loop interval from config
