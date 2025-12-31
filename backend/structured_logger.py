import logging
import json
import time
import os
import sys
from logging.handlers import RotatingFileHandler

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

class JSONFormatter(logging.Formatter):
    """Formats logs as a single line of JSON."""
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(), 
            "module": record.module,
        }
        # Add extra fields (context) if passed in the log call
        if hasattr(record, "extra_data"):
            log_record.update(record.extra_data)
        
        return json.dumps(log_record)

def setup_json_logger(name: str):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Avoid adding handlers multiple times
    if logger.handlers:
        return logger

    # 1. File Handler (JSON Lines) - stores in backend/logs/events.jsonl
    log_file_path = os.path.join("logs", "events.jsonl")
    file_handler = RotatingFileHandler(
        log_file_path, 
        maxBytes=10*1024*1024, # 10MB
        backupCount=5
    )
    file_handler.setFormatter(JSONFormatter())
    
    # 2. Console Handler (Simple Text for Debugging)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    
    return logger

# Global instance
logger = setup_json_logger("SECURE_RAG")
