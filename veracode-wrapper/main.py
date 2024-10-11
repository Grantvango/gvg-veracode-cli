import argparse
import os
import requests
import tarfile
import zipfile
import platform

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
    print("Downloading srcclr CLI agent...")
    response = requests.get(SRCCLR_URL, stream=True)
    if response.status_code == 200:
        tarball_path = os.path.join(TEMP_DIR, "srcclr-agent.tgz")
        with open(tarball_path, "wb") as tarball_file:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    tarball_file.write(chunk)
        print(f"Downloaded srcclr CLI agent to {tarball_path}")

        # Extract the tarball
        with tarfile.open(tarball_path, "r:gz") as tar:
            tar.extractall(path=TEMP_DIR)
        print(f"Extracted srcclr CLI agent to {TEMP_DIR}")

        # Make the srcclr binary executable (Unix-like systems)
        if platform.system() != "Windows":
            srcclr_path = os.path.join(TEMP_DIR, "srcclr")
            os.chmod(srcclr_path, 0o755)
            print(f"srcclr CLI agent is set up at {srcclr_path}")
    else:
        print(
            f"Failed to download srcclr CLI agent. Status code: {response.status_code}"
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


def setup_veracode_api_creds(api_id, api_key):
    creds_path = os.path.join(os.path.expanduser("~"), ".veracode", "credentials")
    os.makedirs(os.path.dirname(creds_path), exist_ok=True)
    with open(creds_path, "w") as creds_file:
        creds_file.write(
            f"[default]\nveracode_api_key_id = {api_id}\nveracode_api_key_secret = {api_key}\n"
        )
    print(f"Veracode API credentials set up at {creds_path}")


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
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dir", type=str, help="Directory to process")
    group.add_argument("--url", type=str, help="URL to process")
    parser.add_argument("--api-id", type=str, help="Veracode API ID")
    parser.add_argument("--api-key", type=str, help="Veracode API Key")

    args = parser.parse_args()

    if args.dir:
        process_directory(args.dir)
    elif args.url:
        process_url(args.url)

    # Download and set up srcclr CLI agent
    download_and_setup_srcclr()

    # Download and set up Veracode pipeline scanner
    download_and_setup_veracode_pipeline_scanner()

    # Download and set up Veracode wrapper
    download_and_setup_veracode_wrapper()

    # Download and set up Veracode CLI tool
    download_and_setup_veracode_cli()

    # Set up Veracode API credentials if provided
    if args.api_id and args.api_key:
        setup_veracode_api_creds(args.api_id, args.api_key)


if __name__ == "__main__":
    main()
