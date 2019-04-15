"""
Tests for the auth convenience method
"""

from unittest.mock import patch, mock_open, call, Mock
from copy import deepcopy
from json import dumps as jdumps
from stat import S_IRUSR, S_IWUSR

import pytest

from vault_anyconfig.vault_anyconfig import VaultAnyConfig


@pytest.fixture
def gen_vault_creds():
    """
    Generates sample vault credentials for use in tests
    """

    def _gen_vault_creds():
        vault_creds = {
            "vault_creds": {
                "role_id": "test-role-id",
                "secret_id": "test-secret-id",
                "auth_method": "approle",
            }
        }
        return vault_creds

    return _gen_vault_creds


@patch("vault_anyconfig.vault_anyconfig.Client.is_authenticated")
@patch("vault_anyconfig.vault_anyconfig.Client.auth_approle")
@patch("vault_anyconfig.vault_anyconfig.load_base")
def test_auth_from_file(
    mock_load,
    mock_auth_approle,
    mock_is_authenticated,
    localhost_client,
    gen_vault_creds,
):
    """
    Basic test for the auth_from_file function
    """
    mock_load.return_value = gen_vault_creds()
    mock_is_authenticated.return_value = True

    assert localhost_client.auth_from_file("config.json")

    compare_vault_creds = gen_vault_creds()

    mock_load.assert_called_with("config.json")
    mock_auth_approle.assert_called_with(
        role_id=compare_vault_creds["vault_creds"]["role_id"],
        secret_id=compare_vault_creds["vault_creds"]["secret_id"],
    )
    mock_is_authenticated.assert_called_with()


@patch("vault_anyconfig.vault_anyconfig.Client.is_authenticated")
@patch("vault_anyconfig.vault_anyconfig.load_base")
def test_auth_from_file_bad_method(
    mock_load, mock_is_authenticated, localhost_client, gen_vault_creds
):
    """
    Test that the exception is thrown as expected when using a bad authentication method
    """
    local_vault_creds = gen_vault_creds()
    local_vault_creds["vault_creds"]["auth_method"] = "nothing"
    mock_load.return_value = local_vault_creds
    mock_is_authenticated.return_value = True

    with pytest.raises(NotImplementedError):
        localhost_client.auth_from_file("config.json")

    mock_load.assert_called_with("config.json")


def test_auth_with_passthrough():
    """
    Tests that the auth_from_file will simply be bypassed when using an instance with passthrough
    """
    client = VaultAnyConfig()
    assert client.auth_from_file("config.json")
