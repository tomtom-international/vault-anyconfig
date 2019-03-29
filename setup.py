from __future__ import with_statement

from setuptools import setup, find_packages

import vault_anyconfig

with open("README.md", "r") as fh:
    readme = fh.read()

setup(
    name="vault-anyconfig",
    version=vault_anyconfig.__version__,
    author=vault_anyconfig.__author__,
    author_email=vault_anyconfig.__author_mail__,
    description=vault_anyconfig.__description__,
    long_description=readme,
    long_description_content_type='text/markdown',
    url=("https://github.com/tomtom-international/vault-anyconfig"),
    packages=find_packages(),
    python_requires=">3.5",
    install_requires=[
        "anyconfig==0.9.7",
        "hvac==0.7.2"
    ],
    setup_requires=["pytest-runner>=4.2,<5"],
    tests_require=[
        "coverage>=4.5,<5"
        "pytest>=4.1,<5",
        "pytest-cov>=2.6,<3"
    ],
    entry_points="""
[console_scripts]
vault-anyconfig = vault_anyconfig.cli:main
""",
    dependency_links=[],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "Environment :: Console",
        "Operating System :: OS Independent",
    ],
    license=vault_anyconfig.__license__,
    zip_safe=False,
)
