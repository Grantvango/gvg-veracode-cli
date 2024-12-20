#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Remove previous builds
echo "Cleaning up previous builds..."
rm -rf build/ dist/ *.egg-info

# Create the wheel
echo "Building the wheel..."
python3 setup.py bdist_wheel

echo "Wheel build complete."