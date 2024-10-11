from setuptools import setup, find_packages

setup(
    name="veracode-wrapper",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        # List your package dependencies here
        # e.g., 'numpy', 'requests'
    ],
    author="GVG",
    author_email="gvgpython@gmail.com",
    description="A veracode wrapper - auto package and scan your code using Veracode's agent based scanner and pipeline scan.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Grantvango/gvg-veracode-wrapper.git",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
