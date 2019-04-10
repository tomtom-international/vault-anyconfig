"""
Tests for the init function
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


class TestConfigInit:
    """
    Tests for the init function
    """

    vault_config = {"vault_config": {"url": "http://localhost"}}

    empty_vault_config = {"vault_config": {}}

    @patch("vault_anyconfig.vault_anyconfig.Client.__init__")
    def test_init_no_file(self, mock_hvac_client):
        """
        Tests the init function without a config file (i.e. filling the parameters directly)
        """
        client = VaultAnyConfig(url="http://localhost")
        assert not client.pass_through_flag
        mock_hvac_client.assert_called_with(url="http://localhost")

    @patch("vault_anyconfig.vault_anyconfig.load_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.__init__")
    def test_init_with_file(self, mock_hvac_client, mock_load):
        """
        Tests the init function with an init file
        """
        mock_load.return_value = self.vault_config

        client = VaultAnyConfig(vault_config_file="config.json")

        assert not client.pass_through_flag
        mock_load.assert_called_with("config.json")
        mock_hvac_client.assert_called_with(url="http://localhost")

    def test_init_passthrough_args(self):
        """
        Tests that with an empty argument set, the passthrough flag is set
        """
        client = VaultAnyConfig(**self.empty_vault_config["vault_config"])
        assert client.pass_through_flag

    @patch("vault_anyconfig.vault_anyconfig.load_base")
    def test_init_passthrough_file(self, mock_load):
        """
        Tests that with a vault configuration file where the vault_config section is empty, the passthrough flag is set
        """
        mock_load.return_value = self.empty_vault_config

        client = VaultAnyConfig(vault_config_file="config.json")
        assert client.pass_through_flag
        mock_load.assert_called_with("config.json")

    @patch("vault_anyconfig.vault_anyconfig.load_base")
    def test_init_passthrough_file_no_vault_config_section(self, mock_load):
        """
        Tests that with a vault configuration file where there is no vault_config section, the passthrough flag is set
        """
        mock_load.return_value = {}

        client = VaultAnyConfig(vault_config_file="config.json")
        assert client.pass_through_flag
        mock_load.assert_called_with("config.json")
