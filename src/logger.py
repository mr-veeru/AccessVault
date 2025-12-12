import logging
from logging.handlers import TimedRotatingFileHandler
from pythonjsonlogger import jsonlogger
import os
import sys

# Create logs directory if not exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Logger name
logger = logging.getLogger("accessvault")

# Get log level from config (defaults to INFO if not set)
# Import here to avoid circular imports
def get_log_level():
    """Get log level from environment or config, defaulting to INFO."""
    from src.config import Config
    log_level_str = Config.LOG_LEVEL
    
    # Convert string to logging level constant
    log_levels = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    
    # Default to INFO if invalid level provided
    return log_levels.get(log_level_str, logging.INFO)

logger.setLevel(get_log_level())

# Clear any existing handlers to avoid duplicates
logger.handlers.clear()

# Log file path with daily rotation
log_file = "logs/accessvault.log"

# Custom TimedRotatingFileHandler that handles Windows file locking issues
class WindowsSafeTimedRotatingFileHandler(TimedRotatingFileHandler):
    def doRollover(self):
        """
        Override doRollover to handle Windows file locking issues gracefully
        """
        try:
            super().doRollover()
        except (OSError, PermissionError) as e:
            # If rollover fails due to file locking, just continue with current file
            # This prevents the application from crashing on Windows
            print(f"Log rollover failed (non-critical): {e}", file=sys.stderr)
            pass

# TimedRotatingFileHandler configuration
# when='midnight' → rotate at midnight
# interval=1 → every 1 day
# backupCount=7 → keep only 7 days of logs
file_handler = WindowsSafeTimedRotatingFileHandler(
    log_file,
    when="midnight",
    interval=1,
    backupCount=7,
    encoding="utf-8",
    delay=True,  # Delay file creation until first log
    utc=False,   # Use local time for rotation
)

# Log file name will include date automatically by handler using suffix
file_handler.suffix = "%Y-%m-%d.log"

# JSON formatter for structured logging
# Format includes: timestamp, level, logger name, message, and any extra fields
json_formatter = jsonlogger.JsonFormatter(
    '%(asctime)s %(name)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    json_ensure_ascii=False
)
file_handler.setFormatter(json_formatter)

# Add file handler to logger
logger.addHandler(file_handler)

# Console handler with human-readable format (for development)
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)
