import logging
import os
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler, RotatingFileHandler
from datetime import datetime, timedelta

# Determine the project root dynamically
# This script is in backend/shared/, so project_root is two levels up.
_project_root = Path(__file__).parent.parent.parent

# Define a global flag and log file path to ensure single file logging
_file_handler_initialized = False # Flag to ensure file handler is added only once
_base_log_file_path = _project_root / 'logs' / 'application.log'

def clean_old_logs(log_dir: Path, retention_days: int = 3, max_total_size_mb: int = 100):
    """
    Deletes log files older than retention_days and ensures total log size doesn't exceed max_total_size_mb.
    More aggressive cleanup to prevent large log files.
    
    Args:
        log_dir: Directory containing log files
        retention_days: Maximum age of log files in days (default: 3 days)
        max_total_size_mb: Maximum total size of all log files in MB (default: 100MB)
    """
    logger = logging.getLogger(__name__)
    total_size = 0
    log_files = []
    
    # Collect all log files with their sizes and dates
    for log_file in log_dir.glob('*.log*'):
        try:
            file_size = log_file.stat().st_size
            total_size += file_size
            
            # Extract date from filename (e.g., application.log.2025-06-09 or application.log.1)
            if log_file.suffix.startswith('.'):
                date_str = log_file.suffix.lstrip('.')
                try:
                    # Try to parse as date (YYYY-MM-DD format)
                    log_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                    log_files.append((log_file, file_size, log_date))
                except ValueError:
                    # Try to parse as number (for RotatingFileHandler backups)
                    try:
                        backup_num = int(date_str)
                        # Estimate date based on file modification time
                        mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                        log_files.append((log_file, file_size, mtime.date()))
                    except ValueError:
                        # Skip files that don't match expected patterns
                        continue
        except Exception as e:
            logger.error(f"Error processing log file {log_file}: {e}")
            continue
    
    # Sort by date (oldest first)
    log_files.sort(key=lambda x: x[2])
    
    # Delete files older than retention_days
    cutoff_date = datetime.now().date() - timedelta(days=retention_days)
    for log_file, file_size, log_date in log_files:
        if log_date < cutoff_date:
            try:
                os.remove(log_file)
                total_size -= file_size
                logger.info(f"Deleted old log file: {log_file} (age: {datetime.now().date() - log_date} days)")
            except Exception as e:
                logger.error(f"Error deleting log file {log_file}: {e}")
    
    # If total size still exceeds limit, delete oldest files
    max_total_size_bytes = max_total_size_mb * 1024 * 1024
    if total_size > max_total_size_bytes:
        logger.warning(f"Total log size ({total_size / (1024*1024):.1f}MB) exceeds limit ({max_total_size_mb}MB). Cleaning up...")
        
        for log_file, file_size, log_date in log_files:
            if total_size <= max_total_size_bytes:
                break
            try:
                os.remove(log_file)
                total_size -= file_size
                logger.info(f"Deleted log file due to size limit: {log_file}")
            except Exception as e:
                logger.error(f"Error deleting log file {log_file}: {e}")

def setup_logging(name, max_file_size_mb: int = None, backup_count: int = None, retention_days: int = None):
    """
    Sets up a centralized logging configuration with aggressive rotation and cleanup.
    
    Args:
        name (str): The name of the logger, typically __name__ of the module
        max_file_size_mb (int): Maximum size of each log file in MB before rotation
        backup_count (int): Number of backup files to keep per rotation
        retention_days (int): Maximum age of log files in days
    
    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    global _file_handler_initialized

    # Configure the root logger with a single file handler and stream handler only once
    if not _file_handler_initialized:
        log_dir = _project_root / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)

        formatter = logging.Formatter('[%(asctime)s] - %(name)s - %(levelname)s - %(message)s')

        # Use configuration values or defaults
        from shared.config import Config
        max_file_size_mb = max_file_size_mb or Config.LOG_MAX_FILE_SIZE_MB
        backup_count = backup_count or Config.LOG_BACKUP_COUNT
        retention_days = retention_days or Config.LOG_RETENTION_DAYS

        # Use RotatingFileHandler for size-based rotation (more aggressive)
        max_bytes = max_file_size_mb * 1024 * 1024
        file_handler = RotatingFileHandler(
            _base_log_file_path, 
            maxBytes=max_bytes, 
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        
        # Add a suffix to rotated files for better identification
        file_handler.namer = lambda name: name.replace(".log", "") + ".log"
        file_handler.suffix = "%Y-%m-%d-%H-%M-%S"
        
        logging.getLogger().addHandler(file_handler)
        logging.getLogger().setLevel(logging.INFO)

        # Add StreamHandler (console output) to the root logger as well
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.DEBUG)
        stream_handler.setFormatter(formatter)
        logging.getLogger().addHandler(stream_handler)

        _file_handler_initialized = True
        
        # Run cleanup when logging is initialized
        clean_old_logs(log_dir, retention_days, Config.LOG_MAX_TOTAL_SIZE_MB)

    return logger 