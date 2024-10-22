import os
import subprocess
import logging

from veracode_wrapper.utils import TEMP_DIR, get_headers
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC


class Srcclr:
    def __init__(self, install_script="srcclr_install.sh"):
        self.install_script_path = os.path.join(
            os.path.dirname(__file__), install_script
        )

    def download_and_setup_srcclr(self):
        """
        Download and setup the srcclr CLI agent
        """
        logging.info(
            "Setting up srcclr CLI agent using local srcclr_install.sh script..."
        )
        install_script_path = os.path.join(
            os.path.dirname(__file__), "..", "scripts", "srcclr_install.sh"
        )

        try:
            # Ensure the script exists
            if not os.path.exists(install_script_path):
                logging.info(
                    f"srcclr_install.sh script not found at {install_script_path}"
                )
                return

            # Make the script executable
            os.chmod(install_script_path, 0o755)

            # Execute the local install.sh script
            subprocess.run(f"{install_script_path}", shell=True, check=True)
            logging.info("srcclr CLI agent is set up successfully.")
        except subprocess.CalledProcessError as e:
            logging.info(
                f"Failed to run local srcclr_install.sh script for srcclr CLI agent. Error: {e}"
            )

    def create_srcclr_agent(workspace_id, agent_name):
        """
        Create a new agent in the Veracode SourceClear platform
        """

        url = f"{SRCCLR_API_BASE_URL}/workspaces/{workspace_id}/agents"
        payload = {"agent_type": "CLI", "name": agent_name}
        response = requests.post(
            url,
            json=payload,
            headers=get_headers(),
            auth=RequestsAuthPluginVeracodeHMAC(),
        )
        if response.status_code == 200:
            logging.info("Agent created successfully.")
            agent = response.json()
            token = agent.get("access_token")
            if token:
                os.environ["SRCCLR_API_TOKEN"] = token
                logging.info("SRCCLR_API_TOKEN environment variable set.")

                # Create or update agent.yml in .srcclr directory
                srcclr_dir = os.path.join(os.path.expanduser("~"), ".srcclr")
                os.makedirs(srcclr_dir, exist_ok=True)
                agent_yml_path = os.path.join(srcclr_dir, "agent.yml")

                agent_data = f"agentAuthorization: {token}\n"

                with open(agent_yml_path, "w") as agent_yml_file:
                    agent_yml_file.write(agent_data)

                os.chmod(agent_yml_path, 0o600)

                logging.info("agent.yml file updated with the new token.")
            return agent.get("id")
        else:
            logging.info(
                f"Failed to create agent. Status code: {response.status_code}, Response: {response.text}"
            )
            return None

    # How can I use teams to only get the workspaces for a specific user?
    # TODO: think about if I need to set this at the beginning or everytime the script runs
    # If I set the env varible it will only be that for script, I could set the agent.yml in .srcclr
    def setup_srcclr_workspace():
        """
        Get the srcclr_workspace ID from the .srcclr/setup file or retrieve it from the API if not present
        """
        srcclr_dir = os.path.join(TEMP_DIR, ".srcclr")
        setup_file = os.path.join(srcclr_dir, "setup")

        # Check if the setup file exists and contains the workspace ID
        if os.path.exists(setup_file):
            with open(setup_file, "r") as file:
                for line in file:
                    if line.startswith("srcclr_workspace ="):
                        return line.split("=")[1].strip()

        # If the workspace ID is not found in the setup file, retrieve it from the API
        logging.info(
            "srcclr_workspace ID not found in setup file. Retrieving from workspaces."
        )
        url = f"{SRCCLR_API_BASE_URL}/workspaces?filter%5Bworkspace%5D=My%20Workspace"
        response = requests.get(
            url, headers=get_headers(), auth=RequestsAuthPluginVeracodeHMAC()
        )
        if response.status_code == 200:
            workspaces = response.json().get("_embedded", {}).get("workspaces", [])
            for workspace in workspaces:
                if workspace["name"] == "My Workspace":
                    workspace_id = workspace["id"]
                    os.makedirs(srcclr_dir, exist_ok=True)
                    with open(setup_file, "a") as file:
                        file.write(f"srcclr_workspace = {workspace_id}\n")
                    logging.info(f"Workspace ID written to setup file.")
                    return workspace_id
            logging.info("Workspace 'My Workspace' not found.")
            return None
        else:
            logging.info(
                f"Failed to retrieve workspaces. Status code: {response.status_code}, Response: {response.text}"
            )
            return None

    def create_srcclr_token(agent_id):
        """
        Create a new token for the agent in the Veracode SourceClear platform
        """
        url = f"{SRCCLR_API_BASE_URL}/agents/{agent_id}/tokens"
        payload = {"description": "Token for srcclr agent"}
        response = requests.post(
            url,
            json=payload,
            headers=get_headers(),
            auth=RequestsAuthPluginVeracodeHMAC(),
        )
        if response.status_code == 201:
            logging.info("Token created successfully.")
            return response.json()
        else:
            logging.info(
                f"Failed to create token. Status code: {response.status_code}, Response: {response.text}"
            )
            return None

    def setup_srcclr_agent(workspace_id):
        """
        Get the srcclr_agent ID from the .srcclr/setup file or retrieve it from the API if not present
        """
        srcclr_dir = os.path.join(TEMP_DIR, ".srcclr")
        setup_file = os.path.join(srcclr_dir, "setup")

        # Check if the setup file exists and contains the agent ID
        if os.path.exists(setup_file):
            with open(setup_file, "r") as file:
                for line in file:
                    if line.startswith("srcclr_agent ="):
                        return line.split("=")[1].strip()

        # If the agent ID is not found in the setup file, retrieve it from the API
        logging.info("srcclr_agent ID not found in setup file. Retrieving from API.")

        url = f"{SRCCLR_API_BASE_URL}/workspaces/{workspace_id}/agents"
        response = requests.get(
            url, headers=get_headers(), auth=RequestsAuthPluginVeracodeHMAC()
        )
        if response.status_code == 200:
            agents = response.json().get("_embedded", {}).get("agents", [])
            for agent in agents:
                if agent["name"].lower() == "cli":
                    agent_id = agent["id"]
                    os.makedirs(srcclr_dir, exist_ok=True)
                    with open(setup_file, "a") as file:
                        file.write(f"srcclr_agent = {agent_id}\n")
                    logging.info(f"Agent ID written to setup file.")
                    return agent_id

            # If no existing agent is found, create a new agent
            logging.info("No existing agent found. Creating a new agent named 'CLI'.")
            return create_srcclr_agent(workspace_id, "CLI")
        logging.info("Issue setting up agent.")
        return None

    def regenerate_srcclr_token(workspace_id, agent_id):
        """
        Regenerate a token for the agent in the Veracode SourceClear platform
        """
        url = f"{SRCCLR_API_BASE_URL}/workspaces/{workspace_id}/agents/{agent_id}/token:regenerate"
        response = requests.post(
            url, headers=get_headers(), auth=RequestsAuthPluginVeracodeHMAC()
        )
        if response.status_code == 200:
            logging.info("Token regenerated successfully.")
            token = response.json().get("access_token")
            if token:
                os.environ["SRCCLR_API_TOKEN"] = token
                logging.info("SRCCLR_API_TOKEN environment variable set.")

                # Create or update agent.yml in .srcclr directory
                srcclr_dir = os.path.join(os.path.expanduser("~"), ".srcclr")
                os.makedirs(srcclr_dir, exist_ok=True)
                agent_yml_path = os.path.join(srcclr_dir, "agent.yml")

                agent_data = f"agentAuthorization: {token}\n"

                with open(agent_yml_path, "w") as agent_yml_file:
                    agent_yml_file.write(agent_data)

                os.chmod(agent_yml_path, 0o600)

                logging.info("agent.yml file updated with the new token.")
            return
        else:
            logging.info(
                f"Failed to regenerate token. Status code: {response.status_code}, Response: {response.text}"
            )
            return

    def setup_srcclr_agent_and_token():
        """
        Set up the srcclr agent and token
        """
        workspace_id = setup_srcclr_workspace()

        if not workspace_id:
            logging.info("Workspace ID was not found or setup incorrectly.")
            return

        agent_id = setup_srcclr_agent(workspace_id)

        if not agent_id:
            logging.info("Agent ID was not found or setup incorrectly.")
            return

        # regenerate_srcclr_token(workspace_id, agent_id)
        # Add something to check if the token is expired and regenerate it
        return

    def locate_srcclr():
        """
        Locate the Veracode SCA agent JAR and JRE in the temporary directory
        """
        base_dir = os.path.join(TEMP_DIR, "srcclr-latest")
        for root, dirs, files in os.walk(base_dir):
            for directory in dirs:
                if directory.startswith("srcclr-"):
                    srcclr_path = os.path.join(root, directory, "bin", "srcclr")
                    # return the file path
                    return srcclr_path

        # for file in files: in dirs:
        #     if file.startswith("srcclr-") and file.endswith(".jar"):
        #         jre_path = os.path.join(root, "jre", "bin", "java")
        #         if os.path.exists(jre_path):
        #             return os.path.join(root, file), jre_path
        raise FileNotFoundError(
            "Veracode SCA agent srcclr not found. Please ensure they are downloaded and set up correctly."
        )

    def grab_srcclr_projects():
        """
        Retrieve projects from the Veracode SourceClear platform for a given workspace ID
        """
        workspace_id = setup_srcclr_workspace()
        if not workspace_id:
            print("Workspace ID not found.")
            return None

        print(workspace_id)

        url = f"{SRCCLR_API_BASE_URL}/workspaces/{workspace_id}"
        response = requests.delete(
            url, headers=get_headers(), auth=RequestsAuthPluginVeracodeHMAC()
        )
        if response.status_code == 200:
            print(response.json())
        else:
            print(
                f"Failed to retrieve projects. Status code: {response.status_code}, Response: {response.text}"
            )
            return None

    def srcclr_scan(directory):
        """
        Run the Veracode SCA agent scan command
        """
        srcclr_path = locate_srcclr()
        # Create scan_results directory within the temp directory
        scan_results_dir = os.path.join(
            TEMP_DIR, "scan_results", os.path.basename(directory)
        )
        os.makedirs(scan_results_dir, exist_ok=True)
        json_output_path = os.path.join(scan_results_dir, "sca_results.json")

        srcclr_scan_command = (
            f"{srcclr_path} scan {directory} --no-upload --json {json_output_path}"
        )
        logging.info(srcclr_scan_command)
        result = subprocess.run(
            srcclr_scan_command.split(), capture_output=True, text=True
        )
        if result.returncode == 0:
            logging.info(result.stdout)
        else:
            logging.info(f"Error running srcclr: {result.stderr}")