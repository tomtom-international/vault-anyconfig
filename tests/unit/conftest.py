"""
Pytest configuration including fixtures
"""
from unittest.mock import patch
from pytest import fixture

from vault_anyconfig.vault_anyconfig import VaultAnyConfig


@fixture
@patch("vault_anyconfig.vault_anyconfig.Client.__init__")
def localhost_client(mock_hvac_client):
    """
    Configures a mock instance of the HVAC client
    """
    return VaultAnyConfig(url="http://localhost")


@fixture
def gen_vault_response_kv1():
    """
    Provides the vault response for kv1 store
    """

    def _gen_vault_response(contents, secret_key):
        vault_response = {"data": {secret_key: contents}}

        return vault_response

    return _gen_vault_response


@fixture
def gen_vault_response_kv2():
    """
    Provides the vault response for kv2 store
    """

    def _gen_vault_response(contents, secret_key):
        vault_response = {"data": {"data": {secret_key: contents}}, "metadata": {"version": "1"}}

        return vault_response

    return _gen_vault_response


@fixture
def gen_input_config():
    """
    Generates an input configuration for providing to a vault client in tests
    """

    def _gen_input_config(
        vault_secrets={"acme.user": "secret/acme/server/user", "acme.pwd": "secret/acme/server/user"}
    ):
        input_config = {
            "acme": {"host": "https://acme.com", "cert_path": "/secret/cert"},
            "vault_secrets": vault_secrets,
        }
        return input_config

    return _gen_input_config


@fixture
def gen_processed_config(gen_input_config):
    """
    Provides a processed configuration (what should result after running input through the client)
    """

    def _gen_processed_config(input_config=gen_input_config()):
        processed_config = {
            "acme": {
                "host": input_config["acme"]["host"],
                "cert_path": input_config["acme"]["cert_path"],
                "user": "test_user",
                "pwd": "test_password",
            }
        }
        return processed_config

    return _gen_processed_config
