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
        vault_response = {"data": {
            "data": {secret_key: contents}},
            "metadata": {"version": "1"}
        }

        return vault_response

    return _gen_vault_response
