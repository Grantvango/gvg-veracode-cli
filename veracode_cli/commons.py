# src/veracode_wrapper/commons.py
import os
import logging

# Set the environment variable for the temporary folder
TEMP_DIR = os.path.join(os.path.expanduser("~"), ".veracode_cli")
os.makedirs(TEMP_DIR, exist_ok=True)

# Configure logging
log_file = "veracode_cli.log"
logging.basicConfig(
    level=logging.INFO,  # change this to Warning, add a flag to change this to info when verbose
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
)

# Suppress debug logs from requests and urllib3
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_headers():
    """
    Get the headers for the API request
    """
    return {"Content-Type": "application/json"}


def cleanup_temp_dir():
    """
    Cleanup the temporary directory
    """
    if os.path.exists(TEMP_DIR):
        for root, dirs, files in os.walk(TEMP_DIR, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(TEMP_DIR)
        logging.info(f"Cleaned up temporary directory: {TEMP_DIR}")
