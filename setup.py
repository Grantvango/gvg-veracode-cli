from setuptools import setup


# Function to read the requirements from requirements.txt
def read_requirements():
    with open("requirements.txt") as req_file:
        return req_file.read().splitlines()


# Setup the package
setup(
    name="veracode-cli",
    version="0.1.0",
    package_dir={"": "veracode_cli"},
    install_requires=read_requirements(),
    author="GVG",
    author_email="gvgpython@gmail.com",
    description="A veracode wrapper for their CLI tools - Pipeline Scan, AutoPackager, and SCA",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Grantvango/gvg-veracode-wrapper.git",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "veracode-cli=veracode_cli.main:main",
        ],
    },
    python_requires=">=3.6",
    license="GPL-3.0",
)
