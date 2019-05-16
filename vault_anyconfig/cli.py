# -*- coding: utf-8 -*-
"""
Reads in a file, adds the Vault secrets to it, then writes out the results to a new file.
"""

import sys
import argparse

from vault_anyconfig.vault_anyconfig import VaultAnyConfig


def parse_args(args):
    """
    Handles the arguments from the user
    """
    parser = argparse.ArgumentParser(
        description="Read in configuration file and populate with Vault stored secrets."
    )
    parser.add_argument(
        "in_file", type=argparse.FileType("r"), help="Configuration file to read in"
    )
    parser.add_argument(
        "out_file",
        type=argparse.FileType("w"),
        help="File to write out after populating",
    )
    parser.add_argument(
        "--file_type", type=str, required=True, help="File type to read and write"
    )
    parser.add_argument(
        "--vault_config", type=str, required=True, help="Vault configuration file."
    )
    parser.add_argument(
        "--vault_creds", type=str, required=True, help="Vault credentials file"
    )
    parser.add_argument(
        "--secret_files_write",
        action="store_false",
        help="Use to pull and write to disk anything in the vault_files section",
    )
    return parser.parse_args(args)


def main():
    """
    Main entrypoint
    """
    args = parse_args(sys.argv[1:])

    client = VaultAnyConfig(vault_config_file=args.vault_config)
    client.auth_from_file(args.vault_creds)

    config = client.load(
        args.in_file,
        process_secret_files=args.secret_files_write,
        ac_parser=args.file_type,
    )

    client.dump(
        config,
        args.out_file,
        process_secret_files=args.secret_files_write,
        ac_parser=args.file_type,
    )


if __name__ == "__main__":
    sys.exit(main())
