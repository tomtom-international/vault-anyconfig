#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from __future__ import with_statement

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

import vault_anyconfig


with open("README.md") as readme_file:
    readme = readme_file.read()

with open("CHANGELOG.md") as changelog_file:
    changelog = changelog_file.read()

requirements = ["anyconfig==0.9.8", "hvac==0.7.2"]

setup_requirements = ["pytest-runner"]

test_requirements = ["pytest", "pytest-cov", "coverage", "hypothesis"]

setup(
    author=vault_anyconfig.__author__,
    author_email=vault_anyconfig.__email__,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Environment :: Console",
        "Operating System :: OS Independent",
    ],
    description="Describe in a short sentence your Python package.",
    entry_points={"console_scripts": ["vault-anyconfig=vault_anyconfig.cli:main"]},
    install_requires=requirements,
    license="Apache Software License 2.0",
    long_description=readme + "\n\n" + changelog,
    long_description_content_type="text/markdown",
    include_package_data=True,
    keywords="vault_anyconfig",
    name=vault_anyconfig.__project__,
    packages=find_packages(include=["vault_anyconfig"]),
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=test_requirements,
    url="https://github.com/tomtom-international/vault-anyconfig",
    version=vault_anyconfig.__version__,
    zip_safe=False,
)
