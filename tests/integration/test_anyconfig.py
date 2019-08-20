"""
Integration tests with anyconfig
"""
import json
from unittest.mock import patch

import pytest
import pyaml

from vault_anyconfig.vault_anyconfig import VaultAnyConfig

PARSER_PARAMS = {
    "arg_names": "parser_dump_function,parser_name",
    "params": [(json.dumps, "json"), (pyaml.dump, "yaml")],
}


@pytest.mark.parametrize(PARSER_PARAMS["arg_names"], PARSER_PARAMS["params"])
@patch("vault_anyconfig.vault_anyconfig.Client.__init__")
def test_init_string(mock_hvac, parser_dump_function, parser_name):
    """
    Tests that using a string to initialize the client will work
    """
    test_config = {"vault_config": {"test_value": 1, "test_value2": "value2"}, "extra_stuff": "test_me"}
    VaultAnyConfig(vault_config_in=parser_dump_function(test_config), ac_parser=parser_name)
    mock_hvac.assert_called_once_with(test_value=1, test_value2="value2")


@pytest.mark.parametrize(PARSER_PARAMS["arg_names"], PARSER_PARAMS["params"])
@patch("vault_anyconfig.vault_anyconfig.Client.is_authenticated")
@patch("vault_anyconfig.vault_anyconfig.Client.auth_approle")
def test_auto_auth(mock_auth_approle, mock_is_authenticated, parser_dump_function, parser_name):
    """
    Tests that string inputs to auto_auth will be correctly parsed
    """
    creds = {"vault_creds": {"auth_method": "approle", "role_id": "test_jim_bob", "secret_id": "test_123password"}}
    mock_is_authenticated.return_value = False

    VaultAnyConfig(url="http://localhost").auto_auth(parser_dump_function(creds), ac_parser=parser_name)

    mock_auth_approle.assert_called_with(
        role_id=creds["vault_creds"]["role_id"], secret_id=creds["vault_creds"]["secret_id"]
    )
    mock_is_authenticated.assert_called_with()
