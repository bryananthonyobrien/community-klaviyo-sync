import logging
import os
from logging.handlers import RotatingFileHandler

def clear_log_files():
    log_files = [
        os.path.expanduser('~/logs/payload.log')  # Only clear payload.log
    ]
    for log_file in log_files:
        if os.path.exists(log_file):  # Ensure the log file exists
            try:
                with open(log_file, 'w'):
                    pass  # This will truncate the file
                print(f"Cleared log file: {log_file}")
            except Exception as e:
                print(f"Error clearing log file {log_file}: {e}")
        else:
            print(f"Log file {log_file} does not exist, skipping.")

def setup_logger():
    logger = logging.getLogger('FlaskApp')

    # Check if the logger already has handlers to avoid duplicate handlers
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)

        log_dir = os.path.expanduser('~/logs')
        log_file = os.path.join(log_dir, 'payload.log')

        # Ensure the log directory exists
        os.makedirs(log_dir, exist_ok=True)

        try:
            # Use RotatingFileHandler to handle log rotation safely
            handler = RotatingFileHandler(log_file, maxBytes=5000000, backupCount=5)
            handler.setLevel(logging.DEBUG)

            # Include PID in the log format
            formatter = logging.Formatter('%(asctime)s - PID: %(process)d - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)

            print(f"Logger setup completed successfully. Logs are stored in {log_file}")
        except OSError as e:
            print(f"Error setting up logger: {e}")

    return logger


# Clear log files before initializing the logger
clear_log_files()

# Initialize logger
app_logger = setup_logger()

