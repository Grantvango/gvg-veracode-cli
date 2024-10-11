# Veracode Wrapper Script

This script automates the process of scanning directories, URLs, or artifact files using Veracode tools. It sets up the necessary tools, validates Veracode API credentials, and performs scans using the Veracode CLI and Pipeline Scanner.

## Prerequisites

- Python 3.x
- Veracode API credentials

## Setup

1. **Clone the repository**:

   ```sh
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Install required Python packages**:

   ```sh
   pip install -r requirements.txt
   ```

3. **Set up Veracode API credentials**:
   Ensure you have your Veracode API ID and Key. The script will prompt you to enter these during setup.

## Usage

### Initial Setup

To set up all necessary tools and validate Veracode API credentials, run:

```sh
python main.py --setup
```
