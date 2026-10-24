"""Setup configuration for KaraQargha CLI OSINT tool."""

import os
from setuptools import find_packages, setup

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="karagargha",
    version="2.0.0",
    description="KaraQargha — Command-Line Open Source Intelligence (OSINT) Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Murad9100",
    url="https://github.com/Murad9100/KaraQargha",
    license="MIT",
    packages=find_packages(include=["karagargha", "karagargha.*"]),
    python_requires=">=3.12",
    install_requires=[
        "colorama>=0.4.6",
        "requests>=2.28.0",
        "phonenumbers>=8.13.0",
        "httpx>=0.24.0",
        "trio>=0.22.0",
        "pyfiglet>=1.0.0",
        "dnspython>=2.4.0",
        "Pillow>=10.0.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "test": [
            "pytest>=7.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "karagargha=karagargha.main:cli_entry",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Environment :: Console",
        "Operating System :: OS Independent",
    ],
    keywords="osint intelligence security reconnaissance breach-check phone-lookup geolocation",
)
