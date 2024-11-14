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
    parse_results,
    cleanup_temp_dir,  # Import the new function
)
from veracode_wrapper.veracode_cli import VeracodeCLI
from veracode_wrapper.srcclr import Srcclr

# TODO: when installing this package, ask them if they want to install pre-commit hooks. Check if


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

    # Define the output path for the results HTML file
    scan_results_dir = os.path.join(TEMP_DIR, "scan_results", package_name)
    os.makedirs(scan_results_dir, exist_ok=True)
    output_report_path = os.path.join(scan_results_dir, "results.html")

    # # Run the Veracode CLI tool to autopackage the directory
    # VeracodeCLI().run_command(
    #     f"package --source {directory} --type directory --trust --output {package_path}"
    # )

    # # Iterate over each file in the package_path directory and run the Veracode pipeline scanner
    # for root, dirs, files in os.walk(package_path):
    #     for file in files:
    #         # Skip hidden files
    #         if file.startswith("."):
    #             logging.debug(f"Skipping hidden file: {file}")
    #             continue

    #         file_path = os.path.join(root, file)
    #         base_file = os.path.splitext(os.path.basename(file_path))[0]
    #         logging.info(f"Kicking off SAST scan on: {base_file}")
    #         VeracodeCLI().run_command(
    #             f"static scan {file_path} --results-file sast_results_{base_file}.json"
    #         )

    #         # Check if file exists
    #         sast_results_path = f"sast_results_{base_file}.json"
    #         if os.path.exists(sast_results_path):
    #             # Move the JSON file to the package_path directory
    #             new_sast_results_path = os.path.join(
    #                 scan_results_dir, f"sast_results_{base_file}.json"
    #             )
    #             shutil.move(sast_results_path, new_sast_results_path)
    #             logging.debug(f"Moved {sast_results_path} to {new_sast_results_path}")
    #         else:
    #             logging.debug(f"Failed to find {sast_results_path}")

    # Set up the Veracode SCA agent and token
    srcclr = Srcclr()
    srcclr.setup_srcclr_agent_and_token()

    # Run the Veracode SCA agent scan
    logging.info(f"Running Veracode agent-based scan on: {directory}")
    # Run srcclr_scan and handle any errors
    try:
        srcclr.srcclr_scan(directory)
    except Exception as e:
        logging.debug(f"srcclr_scan failed: {e}")

    parse_results(scan_results_dir, output_report_path)


def main():
    """
    Main function to parse command line arguments and run the appropriate logic
    """
    parser = argparse.ArgumentParser(
        description="Tool used to perform SAST/SCA scan an application directory."
    )
    parser.add_argument(
        "--setup", "-s", action="store_true", help="Set up all tools and credentials"
    )
    parser.add_argument(
        "--cleanup", "-c", action="store_true", help="Clean up the temporary directory"
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--dir", "-d", type=str, help="Directory to process")

    args = parser.parse_args()

    # Clean up the temporary directory
    if args.cleanup:
        cleanup_temp_dir()
        logging.info("Temporary directory cleaned up.")
        return

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
