import argparse
import os
import requests
import tarfile
import zipfile
import platform
import subprocess
import logging

from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

# Set the environment variable for the temporary folder
TEMP_DIR = os.path.join(os.path.expanduser("~"), ".veracode_tmp")
os.makedirs(TEMP_DIR, exist_ok=True)

VERACODE_PIPELINE_SCANNER_URL = (
    "https://downloads.veracode.com/securityscan/pipeline-scan-LATEST.zip"
)
SRCCLR_API_BASE_URL = "https://api.veracode.com/srcclr/v3"

# Set up logging
log_dir = os.path.join(TEMP_DIR, "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "veracode_pipeline_scan.log")
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def get_headers():
    """
    Get the headers for the API request
    """
    return {"Content-Type": "application/json"}


def download_and_setup_srcclr():
    """
    Download and setup the srcclr CLI agent
    """
    print("Setting up srcclr CLI agent using local srcclr_install.sh script...")
    install_script_path = os.path.join(os.path.dirname(__file__), "srcclr_install.sh")

    try:
        # Ensure the script exists
        if not os.path.exists(install_script_path):
            print(f"srcclr_install.sh script not found at {install_script_path}")
            return

        # Make the script executable
        os.chmod(install_script_path, 0o755)

        # Execute the local install.sh script
        subprocess.run(f"{install_script_path}", shell=True, check=True)
        print("srcclr CLI agent is set up successfully.")
    except subprocess.CalledProcessError as e:
        print(
            f"Failed to run local srcclr_install.sh script for srcclr CLI agent. Error: {e}"
        )


def download_and_setup_veracode_pipeline_scanner():
    """
    Download and setup the Veracode pipeline scanner
    """
    print("Downloading Veracode pipeline scanner...")
    response = requests.get(VERACODE_PIPELINE_SCANNER_URL, stream=True)
    if response.status_code == 200:
        zip_path = os.path.join(TEMP_DIR, "pipeline-scan-LATEST.zip")
        with open(zip_path, "wb") as zip_file:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    zip_file.write(chunk)
        print(f"Downloaded Veracode pipeline scanner to {zip_path}")

        # Extract the zip file to .veracode_tmp/pipeline_scanner-latest
        extraction_dir = os.path.join(TEMP_DIR, "pipeline_scanner-latest")
        os.makedirs(extraction_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extraction_dir)
        print(f"Extracted Veracode pipeline scanner to {extraction_dir}")

        # Remove the zip file after extraction
        os.remove(zip_path)
        print(f"Removed the zip file {zip_path}")
    else:
        print(
            f"Failed to download Veracode pipeline scanner. Status code: {response.status_code}"
        )


def download_and_setup_veracode_cli():
    """
    Download and setup the Veracode CLI tool
    """
    print("Setting up Veracode CLI tool using local veracode_cli_install.sh script...")
    install_script_path = os.path.join(
        os.path.dirname(__file__), "veracode_cli_install.sh"
    )

    try:
        # Ensure the script exists
        if not os.path.exists(install_script_path):
            print(f"veracode_cli_install.sh script not found at {install_script_path}")
            return

        # Make the script executable
        os.chmod(install_script_path, 0o755)

        # Execute the local install.sh script
        subprocess.run(f"{install_script_path}", shell=True, check=True)
        print("Veracode CLI tool is set up successfully.")
    except subprocess.CalledProcessError as e:
        print(
            f"Failed to run local veracode_cli_install.sh script for Veracode CLI tool. Error: {e}"
        )


def validate_setup():
    """
    Validate the setup by checking if the tools are installed and the Veracode API credentials are set up
    """
    creds_path = os.path.join(os.path.expanduser("~"), ".veracode", "credentials")

    if not os.path.exists(creds_path):
        print("Veracode API credentials not found. Please set up the credentials.")
        setup_veracode_api_creds()

    # Send a simple API request to Veracode to validate credentials
    url = "https://api.veracode.com/appsec/v1/applications"
    response = requests.get(
        url, headers=get_headers(), auth=RequestsAuthPluginVeracodeHMAC()
    )

    if response.status_code == 200:
        print(
            "Validation complete. All tools are set up and Veracode API credentials are valid."
        )
        return True
    else:
        print(
            f"Failed to validate Veracode API credentials. Status code: {response.status_code}, Response: {response.text}"
        )
        return False


def setup_veracode_api_creds():
    """
    Set up the Veracode API credentials
    """
    api_id = input("Enter your Veracode API ID: ")
    api_key = input("Enter your Veracode API Key: ")

    creds_path = os.path.join(os.path.expanduser("~"), ".veracode", "credentials")
    os.makedirs(os.path.dirname(creds_path), exist_ok=True)
    with open(creds_path, "w") as creds_file:
        creds_file.write(
            f"[default]\nveracode_api_key_id = {api_id}\nveracode_api_key_secret = {api_key}\n"
        )
    print(f"Veracode API credentials set up at {creds_path}")


def create_agent(agent_name):
    """
    Create a new agent in the Veracode SourceClear platform
    """
    url = f"{SRCCLR_API_BASE_URL}/agents"
    payload = {"name": agent_name}
    response = requests.post(
        url, json=payload, headers=get_headers(), auth=RequestsAuthPluginVeracodeHMAC()
    )
    if response.status_code == 201:
        print("Agent created successfully.")
        return response.json()
    else:
        print(
            f"Failed to create agent. Status code: {response.status_code}, Response: {response.text}"
        )
        return None


def create_token(agent_id):
    """
    Create a new token for the agent in the Veracode SourceClear platform
    """
    url = f"{SRCCLR_API_BASE_URL}/agents/{agent_id}/tokens"
    payload = {"description": "Token for srcclr agent"}
    response = requests.post(
        url, json=payload, headers=get_headers(), auth=RequestsAuthPluginVeracodeHMAC()
    )
    if response.status_code == 201:
        print("Token created successfully.")
        return response.json()
    else:
        print(
            f"Failed to create token. Status code: {response.status_code}, Response: {response.text}"
        )
        return None


def setup_srcclr_agent_and_token(agent_name):
    """
    Set up the SourceClear agent and token
    """
    agent = create_agent(agent_name)
    if agent:
        agent_id = agent.get("id")
        token = create_token(agent_id)
        if token:
            print(f"Agent ID: {agent_id}")
            print(f"Token: {token.get('token')}")
        else:
            print("Failed to create token.")
    else:
        print("Failed to create agent.")


def process_directory(directory):
    """
    Process the given directory
    """
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
    """
    Process the given URL
    """
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


def locate_pipeline_scan():
    """
    Locate the Veracode Pipeline Scanner JAR in the temporary directory
    """
    base_dir = os.path.join(
        os.path.expanduser("~"), ".veracode_tmp", "pipeline_scanner-latest"
    )
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file == "pipeline-scan.jar":
                return os.path.join(root, file)
    raise FileNotFoundError(
        "Pipeline Scanner JAR not found. Please ensure it is downloaded and set up correctly."
    )


def veracode_pipeline_scan(command):
    """
    Run the Veracode Pipeline Scanner command
    """
    # # Log prerequisites
    # logging.info("Checking prerequisites for Veracode Pipeline Scan...")

    # # Check Java installation
    # java_version_result = subprocess.run(
    #     ["java", "-version"], capture_output=True, text=True
    # )
    # if java_version_result.returncode == 0:
    #     logging.info("Java is installed.")
    #     logging.info(f"Java version: {java_version_result.stderr.splitlines()[0]}")
    # else:
    #     logging.error("Java is not installed. Please install Java to proceed.")
    #     return

    # # Check for JAVA_HOME environment variable
    # java_home = os.environ.get("JAVA_HOME")
    # if java_home:
    #     logging.info(f"JAVA_HOME is set to: {java_home}")
    # else:
    #     logging.warning("JAVA_HOME is not set. It is recommended to set JAVA_HOME.")

    # # Check for internet connectivity
    # try:
    #     requests.get("https://analysiscenter.veracode.com", timeout=5)
    #     logging.info("Internet connectivity is available.")
    # except requests.ConnectionError:
    #     logging.error(
    #         "No internet connectivity. Please ensure you have an active internet connection."
    #     )
    #     return

    # Locate the pipeline-scan.jar file
    pipeline_scan_path = locate_pipeline_scan()
    logging.info(f"Located pipeline-scan.jar at: {pipeline_scan_path}")

    # Run the pipeline scan command
    result = subprocess.run(
        ["java", "-jar", pipeline_scan_path] + command.split(),
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        logging.info("Pipeline scan completed successfully.")
        print(result.stdout)
    else:
        logging.error(f"Pipeline scan failed with error: {result.stderr}")


def locate_veracode_cli():
    """
    Locate the Veracode CLI script in the temporary directory
    """
    base_dir = os.path.join(
        os.path.expanduser("~"), ".veracode_tmp", "veracode-cli-latest"
    )
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file == "veracode":
                return os.path.join(root, file)
    raise FileNotFoundError(
        "Veracode CLI script not found. Please ensure it is downloaded and set up correctly."
    )


def veracode_cli(command):
    """
    Run the Veracode CLI command
    """
    veracode_cli_path = locate_veracode_cli()
    result = subprocess.run(
        [veracode_cli_path] + command.split(), capture_output=True, text=True
    )
    if result.returncode == 0:
        print(result.stdout)
    else:
        print(f"Error: {result.stderr}")


def scan_dir(directory):
    """
    Scan the given directory
    """
    print(f"Scanning directory: {directory}")

    # Create the output directory for autopackager
    package_output_dir = os.path.join(
        os.path.expanduser("~"), ".veracode_tmp", "packages"
    )
    os.makedirs(package_output_dir, exist_ok=True)

    # Define the package name
    package_name = os.path.basename(os.path.normpath(directory))
    package_path = os.path.join(package_output_dir, package_name)

    # Run the Veracode CLI tool to autopackage the directory
    # veracode_cli(
    #     f"package --source {directory} --type directory --trust --output {package_path}"
    # )

    # Run the Veracode pipeline scanner
    veracode_pipeline_scan(f"--file {package_path}")

    # Run the Agent-based scanner
    # Add your agent-based scanner logic here

    print(f"Autopackaged directory: {directory} to {package_path}")


def main():
    """
    Main function to parse command line arguments and run the appropriate logic
    """
    parser = argparse.ArgumentParser(
        description="Process a directory, URL, or artifact"
    )
    parser.add_argument(
        "--setup", action="store_true", help="Set up all tools and credentials"
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--dir", type=str, help="Directory to process")
    group.add_argument("--url", type=str, help="URL to process")
    group.add_argument("--file", type=str, help="Artifact file to process")

    args = parser.parse_args()

    # Setup all tools and credentials
    if args.setup:
        # Download and set up all tools
        # TODO: Add a way to skip this if already set up + using latest versions
        download_and_setup_srcclr()
        download_and_setup_veracode_pipeline_scanner()
        download_and_setup_veracode_cli()

        # Validate setup
        if not validate_setup():
            return

        print(
            "Setup complete. You can now run the script with --dir, --url, or --file to scan a directory, URL, or artifact."
        )
        return

    # Validate that either --dir, --url, or --file is provided
    if args.dir is None and args.url is None and args.file is None:
        parser.error("No action requested, add --dir, --url, or --file")

    # Process the directory, URL, or artifact
    if args.dir:
        print(f"Processing directory: {args.dir}")
        scan_dir(args.dir)
    elif args.url:
        print(f"Processing URL: {args.url}")
    elif args.file:
        print(f"Processing artifact file: {args.file}")


if __name__ == "__main__":
    main()
