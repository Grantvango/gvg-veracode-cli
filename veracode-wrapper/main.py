import argparse
import os
import requests
import tarfile
import zipfile
import platform
import subprocess

# Set the environment variable for the temporary folder
TEMP_DIR = os.path.join(os.path.expanduser("~"), ".veracode_tmp")
os.makedirs(TEMP_DIR, exist_ok=True)

SRCCLR_URL = "https://download.sourceclear.com/ci/latest/srcclr-agent.tgz"
VERACODE_PIPELINE_SCANNER_URL = (
    "https://downloads.veracode.com/securityscan/pipeline-scan-LATEST.zip"
)
VERACODE_WRAPPER_URL = "https://repo1.maven.org/maven2/com/veracode/vosp/api/wrappers/vosp-api-wrappers-java/22.4.10.4/vosp-api-wrappers-java-22.4.10.4.jar"
VERACODE_CLI_URL = "https://downloads.veracode.com/securityscan/veracode-cli/installers/veracode-cli-linux.zip"


def download_and_setup_srcclr():
    print("Setting up srcclr CLI agent using local srcclr_install.sh script...")
    install_script_path = os.path.join(os.path.dirname(__file__), "srcclr_install.sh")

    try:
        # Ensure the script exists
        if not os.path.exists(install_script_path):
            print(f"srcclr_install.sh script not found at {install_script_path}")
            return

        # Make the script executable
        os.chmod(install_script_path, 0o755)

        # Execute the local install.sh script with "local" argument
        subprocess.run(f"{install_script_path}", shell=True, check=True)
        print("srcclr CLI agent is set up successfully.")
    except subprocess.CalledProcessError as e:
        print(
            f"Failed to run local srcclr_install.sh script for srcclr CLI agent. Error: {e}"
        )


def download_and_setup_veracode_pipeline_scanner():
    print("Downloading Veracode pipeline scanner...")
    response = requests.get(VERACODE_PIPELINE_SCANNER_URL, stream=True)
    if response.status_code == 200:
        zip_path = os.path.join(TEMP_DIR, "pipeline-scan-LATEST.zip")
        with open(zip_path, "wb") as zip_file:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    zip_file.write(chunk)
        print(f"Downloaded Veracode pipeline scanner to {zip_path}")

        # Extract the zip file
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(TEMP_DIR)
        print(f"Extracted Veracode pipeline scanner to {TEMP_DIR}")

        # Make the pipeline scanner script executable (Unix-like systems)
        if platform.system() != "Windows":
            scanner_path = os.path.join(TEMP_DIR, "pipeline-scan.sh")
            os.chmod(scanner_path, 0o755)
            print(f"Veracode pipeline scanner is set up at {scanner_path}")
    else:
        print(
            f"Failed to download Veracode pipeline scanner. Status code: {response.status_code}"
        )


def download_and_setup_veracode_wrapper():
    print("Downloading Veracode wrapper...")
    response = requests.get(VERACODE_WRAPPER_URL, stream=True)
    if response.status_code == 200:
        jar_path = os.path.join(TEMP_DIR, "veracode-wrapper.jar")
        with open(jar_path, "wb") as jar_file:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    jar_file.write(chunk)
        print(f"Downloaded Veracode wrapper to {jar_path}")
    else:
        print(
            f"Failed to download Veracode wrapper. Status code: {response.status_code}"
        )


def download_and_setup_veracode_cli():
    print("Downloading Veracode CLI tool...")
    response = requests.get(VERACODE_CLI_URL, stream=True)
    if response.status_code == 200:
        zip_path = os.path.join(TEMP_DIR, "veracode-cli.zip")
        with open(zip_path, "wb") as zip_file:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    zip_file.write(chunk)
        print(f"Downloaded Veracode CLI tool to {zip_path}")

        # Extract the zip file
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(TEMP_DIR)
        print(f"Extracted Veracode CLI tool to {TEMP_DIR}")

        # Make the CLI tool executable (Unix-like systems)
        if platform.system() != "Windows":
            cli_path = os.path.join(TEMP_DIR, "veracode", "veracode")
            os.chmod(cli_path, 0o755)
            print(f"Veracode CLI tool is set up at {cli_path}")
    else:
        print(
            f"Failed to download Veracode CLI tool. Status code: {response.status_code}"
        )


def setup_veracode_api_creds():
    api_id = input("Enter your Veracode API ID: ")
    api_key = input("Enter your Veracode API Key: ")

    creds_path = os.path.join(os.path.expanduser("~"), ".veracode", "credentials")
    os.makedirs(os.path.dirname(creds_path), exist_ok=True)
    with open(creds_path, "w") as creds_file:
        creds_file.write(
            f"[default]\nveracode_api_key_id = {api_id}\nveracode_api_key_secret = {api_key}\n"
        )
    print(f"Veracode API credentials set up at {creds_path}")


def validate_setup():
    creds_path = os.path.join(os.path.expanduser("~"), ".veracode", "credentials")
    if not os.path.exists(creds_path):
        print("Veracode API credentials not found. Please set up the credentials.")
        return False

    with open(creds_path, "r") as creds_file:
        lines = creds_file.readlines()
        api_id = lines[1].split(" = ")[1].strip()
        api_key = lines[2].split(" = ")[1].strip()

    # Send a simple API request to Veracode to validate credentials
    url = "https://analysiscenter.veracode.com/api/5.0/getapplist.do"
    headers = {"Authorization": f"Basic {api_id}:{api_key}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print(
            "Validation complete. All tools are set up and Veracode API credentials are valid."
        )
        return True
    else:
        print(
            f"Failed to validate Veracode API credentials. Status code: {response.status_code}"
        )
        return False


def process_directory(directory):
    if os.path.isdir(directory):
        print(f"Processing directory: {directory}")
        # Add your directory processing logic here
        # Example: Create a file in the temporary directory
        temp_file_path = os.path.join(TEMP_DIR, "directory_output.txt")
        with open(temp_file_path, "w") as temp_file:
            temp_file.write(f"Processed directory: {directory}\n")
        print(f"Output written to {temp_file_path}")
    else:
        print(f"Error: {directory} is not a valid directory")


def process_url(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"Processing URL: {url}")
            # Add your URL processing logic here
            # Example: Create a file in the temporary directory
            temp_file_path = os.path.join(TEMP_DIR, "url_output.txt")
            with open(temp_file_path, "w") as temp_file:
                temp_file.write(f"Processed URL: {url}\n")
            print(f"Output written to {temp_file_path}")
        else:
            print(f"Error: Unable to access URL {url}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description="Process a directory or URL")
    parser.add_argument(
        "--setup", action="store_true", help="Set up all tools and credentials"
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--dir", type=str, help="Directory to process")
    group.add_argument("--url", type=str, help="URL to process")

    args = parser.parse_args()

    if args.setup:
        # Download and set up all tools
        download_and_setup_srcclr()
        # download_and_setup_veracode_pipeline_scanner()
        # download_and_setup_veracode_wrapper()
        # download_and_setup_veracode_cli()

        # Prompt user to set up Veracode API credentials
        setup_veracode_api_creds()

    #     # Validate setup
    #     if not validate_setup():
    #         return

    #     print(
    #         "Setup complete. You can now run the script with --dir or --url to process a directory or URL."
    #     )
    #     return

    # if args.dir is None and args.url is None:
    #     parser.error("No action requested, add --dir or --url")

    # # Process directory or URL
    # if args.dir:
    #     process_directory(args.dir)
    # elif args.url:
    #     process_url(args.url)


if __name__ == "__main__":
    main()
