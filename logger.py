import logging
from logging.handlers import TimedRotatingFileHandler
import os

# Create logs directory if not exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Logger name
logger = logging.getLogger("accessvault")
logger.setLevel(logging.INFO)  # Can change to DEBUG, WARNING, etc.

# Log file path with daily rotation
log_file = "logs/accessvault.log"

# TimedRotatingFileHandler configuration
# when='midnight' → rotate at midnight
# interval=1 → every 1 day
# backupCount=7 → keep only 7 days of logs
handler = TimedRotatingFileHandler(
    log_file,
    when="midnight",
    interval=1,
    backupCount=7,
    encoding="utf-8",
)

# Log file name will include date automatically by handler using suffix
handler.suffix = "%Y-%m-%d.log"

# Log format
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)

# Add handler to logger
logger.addHandler(handler)

# Optional: also log to console
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)
