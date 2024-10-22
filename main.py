import argparse
import os
import requests
import zipfile
import subprocess
import shutil
import logging
import logging.handlers

from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
from veracode_wrapper.utils import (
    get_headers,
    TEMP_DIR,
    validate_setup,
    parse_sast_results,
)
from veracode_wrapper.veracode_cli import VeracodeCLI
from veracode_wrapper.srcclr import Srcclr


def scan_dir(directory):
    """
    Scan the given directory
    """
    logging.info(f"Scanning directory: {directory}")

    # Create the output directory for autopackager
    package_output_dir = os.path.join(TEMP_DIR, "packages")
    os.makedirs(package_output_dir, exist_ok=True)

    # Define the package name
    package_name = os.path.basename(os.path.normpath(directory))
    package_path = os.path.join(package_output_dir, package_name)

    # Run the Veracode CLI tool to autopackage the directory
    VeracodeCLI().run_command(
        f"package --source {directory} --type directory --trust --output {package_path}"
    )

    # Iterate over each file in the package_path directory and run the Veracode pipeline scanner
    for root, dirs, files in os.walk(package_path):
        for file in files:
            # Skip hidden files
            if file.startswith("."):
                logging.info(f"Skipping hidden file: {file}")
                continue

            file_path = os.path.join(root, file)
            base_file = os.path.splitext(os.path.basename(file_path))[0]
            output_path = os.path.join(root, f"{base_file}.html")
            logging.info(
                f"Kicking off SAST Scan - Veracode pipeline scan on: {file_path}"
            )
            VeracodeCLI().run_command(
                f"static scan {file_path} --results-file sast_results_{base_file}.json"
            )

            # Check if file exists
            if os.path.exists(f"sast_results_{base_file}.json"):
                parse_sast_results(f"sast_results_{base_file}.json", output_path)

    # Set up the Veracode SCA agent and token
    Srcclr().setup_srcclr_agent_and_token()

    # Run the Veracode SCA agent scan
    logging.info(f"Running Veracode agent-based scan on: {directory}")
    # Run srcclr_scan and handle any errors
    try:
        Srcclr().srcclr_scan(directory)
    except Exception as e:
        logging.error(f"srcclr_scan failed: {e}")


def main():
    """
    Main function to parse command line arguments and run the appropriate logic
    """
    parser = argparse.ArgumentParser(
        description="Tool used to perform SAST/SCA scan an application directory."
    )
    parser.add_argument(
        "--setup", action="store_true", help="Set up all tools and credentials"
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--dir", type=str, help="Directory to process")

    args = parser.parse_args()

    # Setup all tools and credentials
    if args.setup:
        # Download and set up all tools
        # TODO: Add a way to skip this if already set up + using latest versions
        veracode_cli = VeracodeCLI()
        veracode_cli.download_and_setup_veracode_cli()

        srcclr = Srcclr()
        srcclr.download_and_setup_srcclr()

        # Validate setup
        if not validate_setup():
            return

        logging.info(
            "Setup complete. You can now run the script with --dir <directory> to scan a directory."
        )
        return

    # Validate that --dir was provided
    if args.dir is None:
        parser.error("No action requested, add --dir")

    # Process the directory, URL, or artifact
    if args.dir:
        scan_dir(args.dir)


if __name__ == "__main__":
    main()
