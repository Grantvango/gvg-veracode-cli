# src/veracode_wrapper/commons.py
import os
import logging
import requests
import yaml
import json

from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC


# Set the environment variable for the temporary folder
TEMP_DIR = os.path.join(os.path.expanduser("~"), ".veracode_wrapper")
os.makedirs(TEMP_DIR, exist_ok=True)

# Configure logging
log_file = "veracode-wrapper.log"
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


def validate_setup():
    """
    Validate the setup by checking if the tools are installed and the Veracode API credentials are set up
    """
    creds_path = os.path.join(os.path.expanduser("~"), ".veracode", "credentials")

    if not os.path.exists(creds_path):
        logging.info(
            "Veracode API credentials not found. Please set up the credentials."
        )
        setup_veracode_api_creds()

    # Send a simple API request to Veracode to validate credentials
    url = "https://api.veracode.com/appsec/v1/applications"
    response = requests.get(
        url, headers=get_headers(), auth=RequestsAuthPluginVeracodeHMAC()
    )

    if response.status_code == 200:
        logging.info(
            "Validation complete. All tools are set up and Veracode API credentials are valid."
        )
        return True
    else:
        logging.info(
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
    logging.info(f"Veracode API credentials set up at {creds_path}")

    yaml_creds_path = os.path.join(os.path.expanduser("~"), ".veracode", "veracode.yml")
    os.makedirs(os.path.dirname(yaml_creds_path), exist_ok=True)
    creds_data = {"api": {"key-id": api_id, "key-secret": api_key}}
    with open(yaml_creds_path, "w") as yaml_creds_file:
        yaml.dump(creds_data, yaml_creds_file, default_flow_style=False)
    logging.info(f"Veracode API credentials set up at {yaml_creds_path}")


def parse_sast_results(json_file_path, output_html_path):
    """
    Parse the SAST results JSON file and create an HTML report for the findings
    """
    with open(json_file_path, "r") as json_file:
        data = json.load(json_file)

    findings = data.get("findings", [])
    modules = data.get("modules", [])

    html_content = """
    <html>
    <head>
        <title>SAST Results Report</title>
        <style>
            body { font-family: Arial, sans-serif; }
            table { width: 100%; border-collapse: collapse; }
            th, td { border: 1px solid #ddd; padding: 8px; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>SAST Results Report</h1>
    """

    # Add modules as the title of the table
    if modules:
        html_content += f"<h2>{modules[0]}</h2>"

    html_content += """
        <table>
            <tr>
                <th>Title</th>
                <th>Issue ID</th>
                <th>Severity</th>
                <th>Issue Type</th>
                <th>CWE ID</th>
                <th>Description</th>
                <th>File</th>
                <th>Line</th>
                <th>Function Name</th>
            </tr>
    """

    for finding in findings:
        title = finding.get("title", "N/A")
        issue_id = finding.get("issue_id", "N/A")
        severity = finding.get("severity", "N/A")
        issue_type = finding.get("issue_type", "N/A")
        cwe_id = finding.get("cwe_id", "N/A")
        description = finding.get("display_text", "N/A")
        file_info = finding.get("files", {}).get("source_file", {})
        file = file_info.get("file", "N/A")
        line = file_info.get("line", "N/A")
        function_name = file_info.get("function_name", "N/A")

        html_content += f"""
        <tr>
            <td>{title}</td>
            <td>{issue_id}</td>
            <td>{severity}</td>
            <td>{issue_type}</td>
            <td>{cwe_id}</td>
            <td>{description}</td>
            <td>{file}</td>
            <td>{line}</td>
            <td>{function_name}</td>
        </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    with open(output_html_path, "w") as html_file:
        html_file.write(html_content)

    logging.info(f"HTML report generated at {output_html_path}")
