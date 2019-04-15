"""
Tests for the init function
"""

from unittest.mock import patch, mock_open, call, Mock
from copy import deepcopy
from json import dumps as jdumps
from stat import S_IRUSR, S_IWUSR

import pytest

from vault_anyconfig.vault_anyconfig import VaultAnyConfig


@pytest.fixture
def gen_vault_config():
    """
    Generates a vault_config object with a URL (or empty)
    """

    def _gen_vault_config(empty=False, url="http://localhost"):
        if not empty:
            return {"vault_config": {"url": url}}
        return {"vault_config": {}}

    return _gen_vault_config


@patch("vault_anyconfig.vault_anyconfig.Client.__init__")
def test_init_no_file(mock_hvac_client):
    """
    Tests the init function without a config file (i.e. filling the parameters directly)
    """
    client = VaultAnyConfig(url="http://localhost")
    assert not client.pass_through_flag
    mock_hvac_client.assert_called_with(url="http://localhost")


@patch("vault_anyconfig.vault_anyconfig.load_base")
@patch("vault_anyconfig.vault_anyconfig.Client.__init__")
def test_init_with_file(mock_hvac_client, mock_load, gen_vault_config):
    """
    Tests the init function with an init file
    """
    mock_load.return_value = gen_vault_config()

    client = VaultAnyConfig(vault_config_file="config.json")

    assert not client.pass_through_flag
    mock_load.assert_called_with("config.json")
    mock_hvac_client.assert_called_with(url="http://localhost")


def test_init_passthrough_args(gen_vault_config):
    """
    Tests that with an empty argument set, the passthrough flag is set
    """
    client = VaultAnyConfig(**gen_vault_config(empty=True)["vault_config"])
    assert client.pass_through_flag


@patch("vault_anyconfig.vault_anyconfig.load_base")
def test_init_passthrough_file(mock_load, gen_vault_config):
    """
    Tests that with a vault configuration file where the vault_config section is empty, the passthrough flag is set
    """
    mock_load.return_value = gen_vault_config(empty=True)

    client = VaultAnyConfig(vault_config_file="config.json")
    assert client.pass_through_flag
    mock_load.assert_called_with("config.json")


@patch("vault_anyconfig.vault_anyconfig.load_base")
def test_init_passthrough_file_no_vault_config_section(mock_load):
    """
    Tests that with a vault configuration file where there is no vault_config section, the passthrough flag is set
    """
    mock_load.return_value = {}

    client = VaultAnyConfig(vault_config_file="config.json")
    assert client.pass_through_flag
    mock_load.assert_called_with("config.json")
