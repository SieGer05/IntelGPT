from structured_logger import logger
import time

print("Testing logger...")
logger.info("Test log entry")
logger.info("Test request", extra={"extra_data": {"event": "test_event", "duration": 0.1}})
print("Logger test complete. Check logs/events.jsonl")
