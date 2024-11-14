# src/veracode_wrapper/commons.py
import os
import logging
import requests
import yaml
import json
from datetime import datetime

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
        logging.debug(f"Cleaned up temporary directory: {TEMP_DIR}")


def cleanup_packages_dir():
    """
    Cleanup the packages directory within the temporary directory
    """
    packages_dir = os.path.join(TEMP_DIR, "packages")
    if os.path.exists(packages_dir):
        for root, dirs, files in os.walk(packages_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(packages_dir)
        logging.debug(f"Cleaned up packages directory: {packages_dir}")


def validate_setup():
    """
    Validate the setup by checking if the tools are installed and the Veracode API credentials are set up
    """
    creds_path = os.path.join(os.path.expanduser("~"), ".veracode", "credentials")

    if not os.path.exists(creds_path):
        logging.debug(
            "Veracode API credentials not found. Please set up the credentials."
        )
        setup_veracode_api_creds()

    # Send a simple API request to Veracode to validate credentials
    url = "https://api.veracode.com/appsec/v1/applications"
    response = requests.get(
        url, headers=get_headers(), auth=RequestsAuthPluginVeracodeHMAC()
    )

    if response.status_code == 200:
        logging.debug(
            "Validation complete. All tools are set up and Veracode API credentials are valid."
        )
        return True
    else:
        logging.debug(
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
    logging.debug(f"Veracode API credentials set up at {creds_path}")

    yaml_creds_path = os.path.join(os.path.expanduser("~"), ".veracode", "veracode.yml")
    os.makedirs(os.path.dirname(yaml_creds_path), exist_ok=True)
    creds_data = {"api": {"key-id": api_id, "key-secret": api_key}}
    with open(yaml_creds_path, "w") as yaml_creds_file:
        yaml.dump(creds_data, yaml_creds_file, default_flow_style=False)
    logging.debug(f"Veracode API credentials set up at {yaml_creds_path}")


def parse_results(package_path, output_html_path):
    """
    Parse the SAST and SCA results JSON files and create an HTML report for the findings.
    """

    sast_findings = []
    sca_records = []
    vulnerabilities = []

    # Iterate through the package_path directory to find JSON files
    for root, dirs, files in os.walk(package_path):
        for file in files:
            if file.startswith("sast_results_") and file.endswith(".json"):
                with open(os.path.join(root, file), "r") as json_file:
                    data = json.load(json_file)
                    sast_findings.extend(data.get("findings", []))
            elif file == "sca_results.json":
                with open(os.path.join(root, file), "r") as json_file:
                    data = json.load(json_file)
                    sca_records.extend(data.get("records", []))
                    for record in data.get("records", []):
                        vulnerabilities.extend(record.get("vulnerabilities", []))

    logging.info(f"Found {len(sast_findings)} SAST findings.")
    logging.info(f"Found {len(sca_records)} SCA records.")
    logging.info(f"Found {len(vulnerabilities)} vulnerabilities.")

    # Load the HTML template
    template_path = os.path.join(
        os.path.dirname(__file__), "..", "templates", "sast_sca_report_template.html"
    )
    with open(template_path, "r") as template_file:
        html_content = template_file.read()

    # Generate SAST findings rows
    sast_findings_rows = ""
    for finding in sast_findings:
        cwe_id = finding.get("cwe_id", "N/A")
        issue_type = finding.get("issue_type", "N/A")
        description = finding.get("display_text", "N/A")
        severity = finding.get("severity", "N/A")
        file_info = finding.get("files", {}).get("source_file", {})
        file = file_info.get("file", "N/A")
        line = file_info.get("line", "N/A")
        function_name = file_info.get("function_name", "N/A")

        sast_findings_rows += f"""
        <tr>
            <td>{cwe_id}</td>
            <td>{issue_type}</td>
            <td>{description}</td>
            <td>{severity}</td>
            <td>{file}</td>
            <td>{line}</td>
            <td>{function_name}</td>
        </tr>
        """

    # Generate vulnerabilities rows
    vulnerabilities_rows = ""
    for vulnerability in vulnerabilities:
        cve = vulnerability.get("cve", "N/A")
        title = vulnerability.get("title", "N/A")
        overview = vulnerability.get("overview", "N/A")
        language = vulnerability.get("language", "N/A")
        cvss_score = vulnerability.get("cvssScore", "N/A")
        cvss3_score = vulnerability.get("cvss3Score", "N/A")
        cvss_vector = vulnerability.get("cvssVector", "N/A")
        cvss3_vector = vulnerability.get("cvss3Vector", "N/A")
        has_exploits = vulnerability.get("hasExploits", "N/A")
        veracode_link = vulnerability.get("_links", {}).get("html", "#")
        exploitability = vulnerability.get("exploitability", {})

        vulnerabilities_rows += f"""
        <tr>
            <td><a href="{veracode_link}" target="_blank">{cve}</a></td>
            <td>{title}</td>
            <td>{overview}</td>
            <td>{language}</td>
            <td>{cvss_score}</td>
            <td>{cvss3_score}</td>
            <td>{cvss_vector}</td>
            <td>{cvss3_vector}</td>
            <td>{has_exploits}</td>
            <td class="exploitability-cell">
                <div class="epss-container">
                    <button class="epss-button">EPSS Details</button>
                    <div class="epss-details-dropdown">
                        <strong>Service Status:</strong> {exploitability.get("exploitServiceStatus", "N/A")}<br>
                        <strong>CVE Full:</strong> {exploitability.get("cveFull", "N/A")}<br>
                        <strong>EPSS Status:</strong> {exploitability.get("epssStatus", "N/A")}<br>
                        <strong>EPSS Score:</strong> {exploitability.get("epssScore", "N/A")}<br>
                        <strong>EPSS Percentile:</strong> {exploitability.get("epssPercentile", "N/A")}<br>
                        <strong>EPSS Score Date:</strong> {exploitability.get("epssScoreDate", "N/A")}<br>
                        <strong>EPSS Model Version:</strong> {exploitability.get("epssModelVersion", "N/A")}<br>
                        <strong>EPSS Citation:</strong> <a href="{exploitability.get("epssCitation", "#")}" target="_blank">{exploitability.get("epssCitation", "N/A")}</a><br>
                        <strong>Exploit Observed:</strong> {exploitability.get("exploitObserved", "N/A")}
                    </div>
                </div>
            </td>
        </tr>
        """

    # Generate SCA records rows
    sca_records_rows = ""
    for record in sca_records:
        for library in record.get("libraries", []):
            name = library.get("name", "N/A")
            description = library.get("description", "N/A")
            author = library.get("author", "N/A")
            language = library.get("language", "N/A")
            latest_release = library.get("latestRelease", "N/A")
            latest_release_date = library.get("latestReleaseDate", "N/A")
            if latest_release_date != "N/A":
                try:
                    # Remove 'Z' if present and handle timezone offset
                    if latest_release_date.endswith("Z"):
                        latest_release_date = latest_release_date[:-1]
                    latest_release_date = datetime.fromisoformat(
                        latest_release_date
                    ).strftime("%m/%d/%Y")
                except ValueError:
                    latest_release_date = "Invalid date"

            code_repo_url = library.get("codeRepoUrl", library.get("authorUrl", "#"))
            name_with_link = f'<a href="{code_repo_url}" target="_blank">{name}</a>'

            sca_records_rows += f"""
            <tr>
                <td>{name_with_link}</td>
                <td>{description}</td>
                <td>{author}</td>
                <td>{language}</td>
                <td>{latest_release}</td>
                <td>{latest_release_date}</td>
            </tr>
            """

    # Insert SAST findings rows
    html_content = html_content.replace(
        "<!-- SAST Findings will be inserted here -->", sast_findings_rows
    )

    # Insert vulnerabilities rows
    html_content = html_content.replace(
        "<!-- Vulnerabilities will be inserted here -->", vulnerabilities_rows
    )

    # Insert SCA records rows
    html_content = html_content.replace(
        "<!-- SCA Records will be inserted here -->", sca_records_rows
    )

    # Write the final HTML content to the output file
    with open(output_html_path, "w") as html_file:
        html_file.write(html_content)

    logging.info(f"HTML report generated at {output_html_path}")


# TODO: Add a function to clean up package directories to make sure its scanning only artifacts from CLI auto package
