import threading
import importlib
import logging 
from log_handler import initialize_logging
from configparser import ConfigParser
import time

# Initialize logging
logger = logging.getLogger(__name__)

# Read configuration
config = ConfigParser()
config.read('config.ini')

# Read the main scripts from configuration
scripts = config['main_scripts']['scripts'].split(',')

# Function to dynamically import and run the main function from a script
def get_script_function(script_name, function_name):
    try:
        module = importlib.import_module(script_name)
        return getattr(module, function_name)
    except ImportError as e:
        logger.error(f"Failed to import module {script_name}: {e}")
    except AttributeError as e:
        logger.error(f"Failed to find function '{function_name}' in module {script_name}: {e}")
    return None

# Loop times for each service
service_configs = {script.strip(): int(config[script.strip()]['loop_time_seconds']) for script in scripts}

# Dictionary to keep track of the last successful run time and last start time of each thread
last_successful_run = {service: time.time() for service in service_configs}
last_start_time = {service: time.time() for service in service_configs}

# Dictionary to keep track of the thread instances and shutdown flags
threads = {}
shutdown_flags = {}
success_flags = {}

# Timeout period for each thread in seconds (1 minute for testing)
thread_timeout = 300

# Wrapper to handle timeout
def thread_wrapper(target, service_name, loop_time):
    def wrapped():
        while not shutdown_flags[service_name].is_set():
            timer = threading.Timer(thread_timeout, lambda: shutdown_flags[service_name].set())
            timer.start()
            try:
                last_start_time[service_name] = time.time()
                target()
                last_successful_run[service_name] = time.time()
                success_flags[service_name] = True  # Indicate successful run
                logger.info(f"{service_name} loop successfully completed.")
            except Exception as e:
                logger.error(f"Error in {service_name} thread: {e}")
            timer.cancel()
            if loop_time > 0:
                time.sleep(loop_time)
            else:
                break  # Exit loop if loop_time is not positive (indicates single run)
    return wrapped

# Define thread functions dynamically based on the configuration
thread_functions = {}
for script in scripts:
    script_name = script.strip()
    import_path = config[script_name]['script_name']
    function_name = config[script_name]['function_name']
    main_function = get_script_function(import_path, function_name)
    if main_function:
        thread_functions[script_name] = thread_wrapper(main_function, script_name, service_configs[script_name])

def monitor_threads():
    while True:
        time.sleep(30)  # Check every 30 seconds
        current_time = time.time()
        for thread_name in service_configs.keys():
            last_run_time = last_successful_run[thread_name]
            elapsed_time = current_time - last_run_time
            time_since_start = current_time - last_start_time[thread_name]
            loop_time = service_configs[thread_name]

            if time_since_start < loop_time:
                # If it's not yet time for the next run, skip tracking
                continue

            if not success_flags.get(thread_name, False):
                if elapsed_time > thread_timeout:
                    logger.error(f"Thread {thread_name} has not updated for {elapsed_time:.2f} seconds. Attempting to restart...")
                    if thread_name in threads:
                        shutdown_flags[thread_name].set()  # Signal thread to shutdown
                        threads[thread_name].join(timeout=10)  # Wait for thread to terminate with timeout
                        if threads[thread_name].is_alive():
                            logger.error(f"Thread {thread_name} failed to terminate gracefully, forcing termination...")
                            # Simulate force termination
                            threads[thread_name] = threading.Thread(target=thread_functions[thread_name], name=thread_name)
                            threads[thread_name].daemon = True  # Mark thread as daemon to ensure it terminates with the program
                        # Clear and reset flags and start the thread again
                        shutdown_flags[thread_name].clear()  # Clear the event for reuse
                        last_successful_run[thread_name] = time.time()  # Reset successful run time to current
                        success_flags[thread_name] = False  # Reset success flag
                        logger.info(f"Restarting thread {thread_name}.")
                        # Restart the thread
                        threads[thread_name] = threading.Thread(target=thread_functions[thread_name], name=thread_name)
                        threads[thread_name].start()
                        logger.info(f"Thread {thread_name} restarted successfully.")
                    else:
                        logger.error(f"Thread {thread_name} not found in thread dictionary.")
                else:
                    remaining_time = thread_timeout - elapsed_time
                    logger.error(f"Thread {thread_name} unreleased for {elapsed_time:.2f} seconds. {remaining_time:.2f} seconds left before forced termination.")
            else:
                success_flags[thread_name] = False  # Reset the success flag for the next loop

if __name__ == "__main__":
    logger.info("Executing script main.py")

    # Initialize shutdown flags and success flags, then start threads
    for service in service_configs.keys():
        shutdown_flags[service] = threading.Event()
        success_flags[service] = False
        threads[service] = threading.Thread(target=thread_functions[service], name=service)
        threads[service].start()

    # Start the monitor thread
    monitor_thread = threading.Thread(target=monitor_threads, daemon=True)
    monitor_thread.start()

    # Join threads
    for thread in threads.values():
        thread.join()

    logger.info("Main script execution completed")
