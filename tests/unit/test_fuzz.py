from unittest.mock import patch, mock_open, call, Mock
from copy import deepcopy
from json import dumps as jdumps
from stat import S_IRUSR, S_IWUSR
from os.path import abspath

import pytest
from hypothesis import given, example
import hypothesis.strategies as strat

from vault_anyconfig.vault_anyconfig import VaultAnyConfig


@pytest.fixture
def gen_vault_response():
    """
    Handles providing a Vault response for fuzzing tests
    """

    def _gen_vault_repsonse(key, secret="test_secret"):
        vault_response = {"data": {key: secret}}
        return vault_response

    return _gen_vault_repsonse


@pytest.fixture
def gen_processed_config():
    """
    Provides a processed configuration (what should result after running input through the client)
    """

    def _gen_processed_config(input_config):
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


@patch("vault_anyconfig.vault_anyconfig.Client.read")
@given(
    config_path=strat.text(min_size=1, alphabet=strat.characters(blacklist_categories=("C"))),
    secret_path=strat.text(
        min_size=1,
        alphabet=strat.characters(
            blacklist_categories=("C"),
            blacklist_characters=".",  # Since we separately specify the key, we cannot include "." in the secret path
        ),
    ),
    secret_key=strat.text(
        min_size=1,
        alphabet=strat.characters(
            blacklist_categories=("C"), blacklist_characters="."  # Keys require actual values, not more dot separators
        ),
    ),
)
@example(config_path="acme.test", secret_path="some/secret", secret_key="crt")
def test_fuzz_vault_keys_retrieve(
    mock_hvac_client_read, config_path, secret_path, secret_key, localhost_client, gen_input_config, gen_vault_response
):
    """
    Fuzz test vault_keys_retrieve function
    """
    input_config = gen_input_config(vault_secrets={config_path: secret_path + "." + secret_key})

    mock_hvac_client_read.return_value = gen_vault_response(secret_key, "test_secret")

    config_results = localhost_client._VaultAnyConfig__vault_keys_retrieve(input_config)

    mock_hvac_client_read.assert_called_with(secret_path)

    current_value = config_results
    for key in config_path.split("."):
        current_value = current_value[key]

    assert current_value == "test_secret"
