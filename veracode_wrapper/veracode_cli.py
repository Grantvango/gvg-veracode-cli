import os
import subprocess
import logging
import platform

from veracode_wrapper.utils import TEMP_DIR


class VeracodeCLI:
    def __init__(self):
        self.base_dir = os.path.join(TEMP_DIR, "veracode-cli-latest")

    def download_and_setup_veracode_cli(self):
        """
        Download and setup the Veracode CLI tool
        """
        system = platform.system()
        if system == "Windows":
            logging.info(
                "Setting up Veracode CLI tool using local veracode_cli_install.ps1 script..."
            )
            install_script_path = os.path.join(
                os.path.dirname(__file__), "..", "scripts", "veracode_cli_install.ps1"
            )
            command = ["powershell", "-File", install_script_path]
        else:
            logging.info(
                "Setting up Veracode CLI tool using local veracode_cli_install.sh script..."
            )
            install_script_path = os.path.join(
                os.path.dirname(__file__), "..", "scripts", "veracode_cli_install.sh"
            )
            command = ["bash", install_script_path]

        try:
            # Ensure the script exists
            if not os.path.exists(install_script_path):
                logging.info(
                    f"veracode_cli_install.sh script not found at {install_script_path}"
                )
                return

            # Make the script executable
            os.chmod(install_script_path, 0o755)

            # Execute the local install.sh script
            subprocess.run(f"{install_script_path}", shell=True, check=True)
            logging.info("Veracode CLI tool is set up successfully.")
        except subprocess.CalledProcessError as e:
            logging.info(
                f"Failed to run local veracode_cli_install.sh script for Veracode CLI tool. Error: {e}"
            )

    def locate_veracode_cli(self):
        """
        Locate the Veracode CLI script in the temporary directory
        """
        base_dir = os.path.join(TEMP_DIR, "veracode-cli-latest")
        logging.info(f"Veracode CLI tool found - {base_dir}")
        for root, dirs, files in os.walk(base_dir):
            for file in files:
                if file == "veracode":
                    return os.path.join(root, file)
        raise FileNotFoundError(
            "Veracode CLI script not found. Please ensure it is downloaded and set up correctly."
        )

    def run_command(self, command):
        """
        Run the Veracode CLI command
        """
        veracode_cli_path = self.locate_veracode_cli()
        result = subprocess.run(
            [veracode_cli_path] + command.split(), capture_output=True, text=True
        )
        logging.info(f"Running Veracode CLI command: {command}")
        if result.returncode == 0:
            logging.info("Veracode CLI command completed successfully.")
            return
        else:
            logging.info(f"Error: \n\n{result.stdout}")
            return
