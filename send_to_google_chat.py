#send_to_google_chat.py
import requests
from configparser import ConfigParser
import logging  # Import logging
from log_handler import initialize_logging 

logger = logging.getLogger(__name__)

def send_to_google_chat(message, webhook_url):  # webhook_url added as parameter
    logger.info(f"Sending message to Google Chat: {message}")  # Log message
    payload = {
        "text": message
    }
    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 200:
            logger.info("Successfully sent message to Google Chat")
        else:
            logger.warning(f"Failed to send message to Google Chat. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logger.error(f"An error occurred while sending message to Google Chat: {e}")

def json_send_to_google_chat(json_message, webhook_url):
    logger.info(f"Sending JSON message to Google Chat: {json_message}")  # Log message
    try:
        response = requests.post(webhook_url, headers={'Content-Type': 'application/json'}, data=json_message)
        if response.status_code == 200:
            logger.info("Successfully sent JSON message to Google Chat")
        else:
            logger.warning(f"Failed to send JSON message to Google Chat. Status code: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"An error occurred while sending JSON message to Google Chat: {e}")