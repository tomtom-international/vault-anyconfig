"""
Tests for the auth convenience method
"""
# pylint: disable=attribute-defined-outside-init
# pylint: disable=too-few-public-methods
# pylint: disable=no-self-use
# pylint: disable=unused-argument
from unittest.mock import patch, mock_open, call, Mock
from copy import deepcopy
from json import dumps as jdumps
from stat import S_IRUSR, S_IWUSR

import pytest

from vault_anyconfig.vault_anyconfig import VaultAnyConfig

from .test_config import TestConfig


class TestConfigAuth(TestConfig):
    """
    Tests for the auth convenience method
    """

    vault_creds = {
        "vault_creds": {
            "role_id": "test-role-id",
            "secret_id": "test-secret-id",
            "auth_method": "approle",
        }
    }

    @patch("vault_anyconfig.vault_anyconfig.Client.is_authenticated")
    @patch("vault_anyconfig.vault_anyconfig.Client.auth_approle")
    @patch("vault_anyconfig.vault_anyconfig.load_base")
    def test_auth_from_file(self, mock_load, mock_auth_approle, mock_is_authenticated):
        """
        Basic test for the auth_from_file function
        """
        mock_load.return_value = deepcopy(self.vault_creds)
        mock_is_authenticated.return_value = True

        assert self.client.auth_from_file("config.json")

        mock_load.assert_called_with("config.json")
        mock_auth_approle.assert_called_with(
            role_id=self.vault_creds["vault_creds"]["role_id"],
            secret_id=self.vault_creds["vault_creds"]["secret_id"],
        )
        mock_is_authenticated.assert_called_with()

    @patch("vault_anyconfig.vault_anyconfig.Client.is_authenticated")
    @patch("vault_anyconfig.vault_anyconfig.load_base")
    def test_auth_from_file_bad_method(self, mock_load, mock_is_authenticated):
        """
        Test that the exception is thrown as expected when using a bad authentication method
        """
        vault_creds = deepcopy(self.vault_creds)
        vault_creds["vault_creds"]["auth_method"] = "nothing"
        mock_load.return_value = vault_creds
        mock_is_authenticated.return_value = True

        with pytest.raises(NotImplementedError):
            self.client.auth_from_file("config.json")

        mock_load.assert_called_with("config.json")

    def test_auth_with_passthrough(self):
        """
        Tests that the auth_from_file will simply be bypassed when using an instance with passthrough
        """
        client = VaultAnyConfig()
        assert client.auth_from_file("config.json")
