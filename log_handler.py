import logging
import logging.handlers
import queue
from queue import Queue
import gzip
import shutil
import os
import time

# Initialize a logger for this module
logger = logging.getLogger(__name__)

# Function for gzip compression
def gzip_compress(old_log_path, new_log_path):
    logger.info(f"log_handler - Compressing {old_log_path} to {new_log_path}.")
    with open(old_log_path, 'rb') as f_in:
        with gzip.open(new_log_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    os.remove(old_log_path)
    logger.info(f"log_handler - Compression complete and original log file removed.")

class CustomTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    def doRollover(self):
        # First, let TimedRotatingFileHandler do its rollover
        super().doRollover()
        
        # Compress the old log file
        current_time = self.rolloverAt - self.interval
        time_tuple = self.converter(current_time)
        old_log_path = self.baseFilename + "." + time.strftime(self.suffix, time_tuple)
        new_log_path = old_log_path + ".gz"
        gzip_compress(old_log_path, new_log_path)

        # Reopen the log file
        self.stream = open(self.baseFilename, 'a')
        logger.info("log_handler - Log file reopened.")

# Create a log queue
log_queue = Queue(-1)

# Initialize logging
def initialize_logging():
    global log_handler  # To make log_handler accessible in gzip_compress function
    
    logger.info("Initializing logging...")
    
    if not os.path.exists('log'):
        os.makedirs('log')
        logger.info("Created 'log' directory.")
    
    logging.basicConfig(level=logging.INFO)
    log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    log_handler = CustomTimedRotatingFileHandler('log/main.log', when='midnight', interval=1)
    log_handler.setFormatter(log_formatter)
    log_handler.suffix = '%Y-%m-%d'
    
    logger.addHandler(log_handler)
    
    # Add the log handler to the root logger
    logging.getLogger().addHandler(log_handler)
    
    logger.info("Logging initialized.")
    
    return log_handler

log_handler = initialize_logging()
