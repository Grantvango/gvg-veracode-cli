def download_and_setup_veracode_pipeline_scanner():
    """
    Download and setup the Veracode pipeline scanner
    """
    logging.info("Downloading Veracode pipeline scanner...")
    response = requests.get(VERACODE_PIPELINE_SCANNER_URL, stream=True)
    if response.status_code == 200:
        zip_path = os.path.join(TEMP_DIR, "pipeline-scan-LATEST.zip")
        with open(zip_path, "wb") as zip_file:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    zip_file.write(chunk)
        logging.info(f"Downloaded Veracode pipeline scanner to {zip_path}")

        # Extract the zip file to .veracode_tmp/pipeline_scanner-latest
        extraction_dir = os.path.join(TEMP_DIR, "pipeline_scanner-latest")
        os.makedirs(extraction_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extraction_dir)
        logging.info(f"Extracted Veracode pipeline scanner to {extraction_dir}")

        # Remove the zip file after extraction
        os.remove(zip_path)
        logging.info(f"Removed the zip file {zip_path}")
    else:
        logging.info(
            f"Failed to download Veracode pipeline scanner. Status code: {response.status_code}"
        )


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


def veracode_pipeline_scan(directory, file_path):
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

    # Create scan_results directory within the temp directory
    scan_results_dir = os.path.join(
        TEMP_DIR, "scan_results", os.path.basename(directory)
    )
    os.makedirs(scan_results_dir, exist_ok=True)

    # Update the output file name to be file_path_sast_results.json
    base_name = os.path.basename(file_path)
    name_without_ext = os.path.splitext(base_name)[0]
    json_output_path = os.path.join(scan_results_dir, f"{name_without_ext}.json")

    # Run the Veracode Pipeline Scanner
    scan_command = [
        "java",
        "-jar",
        pipeline_scan_path,
        "-f",
        file_path,
        "-jf",
        f"{name_without_ext}.json",
    ]

    result = subprocess.run(scan_command, capture_output=True, text=True)
    logging.info(
        result.stdout
    )  # Do we need this? Look into why we are getting the error from scanning the packaged file
    if result.returncode != 255:

        # Move the JSON output file to the scan_results_dir
        src_json_path = os.path.join(os.getcwd(), f"{name_without_ext}.json")
        try:
            shutil.move(src_json_path, json_output_path)
        except Exception as e:
            logging.error(f"Failed to move JSON output file: {e}")

        # Delete the filtered_results.json file if it exists
        # TODO: look into filtering on Very High ?
        filtered_results_path = os.path.join(os.getcwd(), "filtered_results.json")
        if os.path.exists(filtered_results_path):
            try:
                os.remove(filtered_results_path)
            except Exception as e:
                logging.error(f"Failed to delete filtered_results.json file: {e}")

        logging.info(
            f"Veracode Pipeline Scanner completed successfully - results can be found {json_output_path}."
        )

    else:
        logging.error(f"Error running Veracode Pipeline Scanner for {file_path}.")
