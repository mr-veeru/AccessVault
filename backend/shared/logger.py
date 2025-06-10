import logging
import os
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime, timedelta

# Determine the project root dynamically
# This script is in backend/shared/, so project_root is two levels up.
_project_root = Path(__file__).parent.parent.parent

# Define a global flag and log file path to ensure single file logging
_file_handler_initialized = False # Flag to ensure file handler is added only once
_base_log_file_path = _project_root / 'logs' / 'application.log'

def clean_old_logs(log_dir: Path, retention_days: int):
    """
    Deletes log files older than retention_days from the specified directory.
    Assumes log files are named with a date suffix like 'application.log.YYYY-MM-DD'.
    """
    for log_file in log_dir.glob('*.log.*'): # Look for rotated log files
        try:
            # Extract date from filename (e.g., application.log.2025-06-09)
            date_str = log_file.suffix.lstrip('.') # Get .YYYY-MM-DD
            log_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            
            if datetime.now().date() - log_date > timedelta(days=retention_days):
                os.remove(log_file)
                print(f"Deleted old log file: {log_file}")
        except ValueError: # Not a date-suffixed log file (e.g., if .log has no date yet)
            continue
        except Exception as e:
            print(f"Error deleting log file {log_file}: {e}")

def setup_logging(name):
    """
    Sets up a centralized logging configuration, directing all logs to a single file
    with daily rotation and automatic cleanup of old logs.

    Args:
        name (str): The name of the logger, typically __name__ of the module (e.g., 'user_service.routes.user_auth').

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO) # Default level for this specific logger

    global _file_handler_initialized

    # Configure the root logger with a single file handler and stream handler only once
    if not _file_handler_initialized:
        log_dir = _project_root / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)

        formatter = logging.Formatter('[%(asctime)s] - %(name)s - %(levelname)s - %(message)s')

        # Add TimedRotatingFileHandler to the root logger
        # Rotates at midnight, keeps no specific backup count as cleanup handles retention
        file_handler = TimedRotatingFileHandler(_base_log_file_path, when='midnight', interval=1, backupCount=0)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logging.getLogger().addHandler(file_handler)
        logging.getLogger().setLevel(logging.INFO) # Set a base level for the root logger

        # Add StreamHandler (console output) to the root logger as well
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.DEBUG) # Typically want more verbose in console
        stream_handler.setFormatter(formatter)
        logging.getLogger().addHandler(stream_handler)

        _file_handler_initialized = True
        
        # Run cleanup when logging is initialized (e.g., on app startup)
        clean_old_logs(log_dir, 7)

    return logger 