#!/bin/sh

# Define the directory to scan
DIRECTORY_TO_SCAN="path/to/your/directory"

# Run the scan_dir function from main.py
python3 path/to/your/repo/main.py --scan-dir $DIRECTORY_TO_SCAN

# Check the exit status of the scan_dir function
if [ $? -ne 0 ]; then
    echo "Scan failed. Aborting push."
    exit 1
fi

# If the scan succeeds, allow the push to proceed
exit 0