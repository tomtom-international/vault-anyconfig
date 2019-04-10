"""
Tests for the configuration loading and dumping capabilities, including Vault mixin
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


class TestConfigMixIn(TestConfig):
    """
    Tests for the load(s) and dump(s) functions
    """

    raw_config = {
        "acme": {"host": "https://acme.com", "cert_path": "/secret/cert"},
        "vault_secrets": {
            "acme.user": "secret/acme/server/user",
            "acme.pwd": "secret/acme/server/user",
        },
    }

    processed_config = {
        "acme": {
            "host": raw_config["acme"]["host"],
            "cert_path": raw_config["acme"]["cert_path"],
            "user": "test_user",
            "pwd": "test_password",
        }
    }

    vault_response = {
        "data": {
            "user": processed_config["acme"]["user"],
            "pwd": processed_config["acme"]["pwd"],
        }
    }

    @patch("vault_anyconfig.vault_anyconfig.dump_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_dump(self, mock_hvac_client_read, mock_dump):
        """
        Basic test of the dump function
        """
        mock_hvac_client_read.return_value = self.vault_response

        raw_config = deepcopy(self.raw_config)

        self.client.dump(raw_config, "out.json")

        mock_hvac_client_read.assert_called_with(
            self.raw_config["vault_secrets"]["acme.user"]
        )
        mock_dump.assert_called_with(self.processed_config, "out.json")

    @patch("vault_anyconfig.vault_anyconfig.dumps_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_dumps(self, mock_hvac_client_read, mock_dumps):
        """
        Basic test of the dumps function
        """
        vault_response = {
            "data": {
                "user": self.processed_config["acme"]["user"],
                "password": self.processed_config["acme"]["pwd"],
            }
        }
        mock_hvac_client_read.return_value = vault_response

        raw_config = deepcopy(self.raw_config)
        raw_config["vault_secrets"]["acme.pwd"] = "secret/acme/server/user.password"
        local_config = deepcopy(raw_config)

        self.client.dumps(local_config)

        mock_hvac_client_read.assert_called_with(
            raw_config["vault_secrets"]["acme.user"]
        )
        mock_dumps.assert_called_with(self.processed_config)

    @patch("vault_anyconfig.vault_anyconfig.load_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_load(self, mock_hvac_client_read, mock_load):
        """
        Basic test of the load function
        """
        mock_hvac_client_read.return_value = self.vault_response
        mock_load.return_value = deepcopy(self.raw_config)

        assert self.client.load("in.json") == self.processed_config

        mock_hvac_client_read.assert_called_with(
            self.raw_config["vault_secrets"]["acme.user"]
        )
        mock_load.assert_called_with("in.json")

    @patch("vault_anyconfig.vault_anyconfig.load_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_load_different_vault_key(self, mock_hvac_client_read, mock_load):
        """
        Tests that a Vault entry with a different key than the configuration dictionary maps correctly
        """
        mock_hvac_client_read.return_value = self.vault_response
        mock_load.return_value = deepcopy(self.raw_config)

        assert self.client.load("in.json") == self.processed_config

        mock_hvac_client_read.assert_called_with(
            self.raw_config["vault_secrets"]["acme.user"]
        )
        mock_load.assert_called_with("in.json")

    @patch("vault_anyconfig.vault_anyconfig.loads_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_loads(self, mock_hvac_client_read, mock_loads):
        """
        Basic test of the loads function
        """
        mock_hvac_client_read.return_value = self.vault_response
        mock_loads.return_value = deepcopy(self.raw_config)
        string_raw_config = jdumps(self.raw_config)
        self.client.loads(string_raw_config)

        mock_hvac_client_read.assert_called_with(
            self.raw_config["vault_secrets"]["acme.user"]
        )
        mock_loads.assert_called_with(string_raw_config)

    @patch("vault_anyconfig.vault_anyconfig.load_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_empty_path_list(self, mock_hvac_client_read, mock_load):
        """
        Tests behavior when an empty key is used in the configuration dictionary
        """
        mock_hvac_client_read.return_value = self.vault_response
        raw_config_edited = deepcopy(self.raw_config)
        raw_config_edited["vault_secrets"][""] = "some_secret"
        mock_load.return_value = deepcopy(raw_config_edited)

        with pytest.raises(KeyError):
            self.client.load("in.json")

        mock_hvac_client_read.assert_called_with(raw_config_edited["vault_secrets"][""])
        mock_load.assert_called_with("in.json")

    @patch("vault_anyconfig.vault_anyconfig.load_base")
    def test_no_vault_secrets(self, mock_load):
        """
        Test the client when there is no Vault configuration performed, but there is a vault_secrets section in the configuration file
        """
        raw_config_edited = deepcopy(self.raw_config)
        del raw_config_edited["vault_secrets"]
        mock_load.return_value = deepcopy(raw_config_edited)

        self.client.load("in.json")

        mock_load.assert_called_with("in.json")

    @patch("vault_anyconfig.vault_anyconfig.load_base")
    def test_load_no_vault_with_secrets(self, mock_load):
        """
        Basic test of the load function
        """
        mock_load.return_value = deepcopy(self.raw_config)

        raw_config_edited = deepcopy(self.raw_config)
        del raw_config_edited["vault_secrets"]

        client = VaultAnyConfig()

        with pytest.warns(UserWarning):
            assert client.load("in.json") == raw_config_edited

        mock_load.assert_called_with("in.json")
