"""
pytest configuration file including fixtures for file handling tests
"""
from os.path import abspath
from pytest import fixture


@fixture
def file_contents(secret="secret_string"):
    return secret


@fixture
def file_path(path="/some/file/secret"):
    return path


@fixture
def file_path_normalized(file_path):
    return abspath(file_path)


@fixture
def secret_path(path="/secret/acme/cert", key=None):
    if key:
        return path + "." + key
    return path


@fixture
def gen_input_config(file_path, secret_path):
    """
    Generates an input configuration for providing to a vault client in tests
    """

    def _gen_input_config(vault_files={file_path: secret_path}):
        input_config = {
            "acme": {"host": "https://acme.com", "cert_path": file_path},
            "vault_files": vault_files,
        }
        return input_config

    return _gen_input_config


@fixture
def gen_processed_config(gen_input_config,):
    """
    Provides a processed configuration (what should result after running input through the client)
    """

    def _gen_processed_config(input_config=gen_input_config()):
        processed_config = {
            "acme": {
                "host": input_config["acme"]["host"],
                "cert_path": input_config["acme"]["cert_path"],
            },
            "vault_files": input_config["vault_files"],
        }
        return processed_config

    return _gen_processed_config


@fixture
def gen_vault_response_kv1(file_contents):
    """
    Provides the vault response for a given processed configuration file
    """

    def _gen_vault_repsonse(file_contents=file_contents, secret_key=""):
        if secret_key != "":
            vault_response = {"data": {secret_key: file_contents}}
        else:
            vault_response = {"data": {"file": file_contents}}

        return vault_response

    return _gen_vault_repsonse
