"""
Tests for the configuration loading and dumping capabilities, including Vault mixin
"""

from unittest.mock import patch, mock_open, call, Mock
from json import dumps as jdumps
from stat import S_IRUSR, S_IWUSR

import pytest

from vault_anyconfig.vault_anyconfig import VaultAnyConfig


@pytest.fixture
def gen_input_config():
    """
    Generates an input configuration for providing to a vault client in tests
    """

    def _gen_input_config(
        vault_secrets={
            "acme.user": "secret/acme/server/user",
            "acme.pwd": "secret/acme/server/user",
        }
    ):
        input_config = {
            "acme": {"host": "https://acme.com", "cert_path": "/secret/cert"},
            "vault_secrets": vault_secrets,
        }
        return input_config

    return _gen_input_config


@pytest.fixture
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


@pytest.fixture
def gen_vault_response_kv1(gen_processed_config):
    """
    Provides the vault response for a given processed configuration file
    """

    def _gen_vault_repsonse(
        processed_config=gen_processed_config(), user_key="user", pwd_key="pwd"
    ):
        vault_response = {
            "data": {
                user_key: processed_config["acme"]["user"],
                pwd_key: processed_config["acme"]["pwd"],
            }
        }
        return vault_response

    return _gen_vault_repsonse


@pytest.fixture
def gen_vault_response_kv2(gen_processed_config):
    """
    Provides the vault response for a given processed configuration file
    """

    def _gen_vault_repsonse(
        processed_config=gen_processed_config(), user_key="user", pwd_key="pwd"
    ):
        vault_response = {
            "data": {
                "data": {
                    user_key: processed_config["acme"]["user"],
                    pwd_key: processed_config["acme"]["pwd"],
                },
                "metadata": {}
            }
        }
        return vault_response

    return _gen_vault_repsonse


@patch("vault_anyconfig.vault_anyconfig.dump_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_dump(
    mock_hvac_client_read,
    mock_dump,
    localhost_client,
    gen_input_config,
    gen_processed_config,
    gen_vault_response_kv1,
):
    """
    Basic test of the dump function
    """
    mock_hvac_client_read.return_value = gen_vault_response_kv1()

    localhost_client.dump(gen_input_config(), "out.json")

    mock_hvac_client_read.assert_called_with(
        gen_input_config()["vault_secrets"]["acme.user"]
    )
    mock_dump.assert_called_with(gen_processed_config(), "out.json")


@patch("vault_anyconfig.vault_anyconfig.dumps_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_dumps(
    mock_hvac_client_read,
    mock_dumps,
    localhost_client,
    gen_input_config,
    gen_processed_config,
    gen_vault_response_kv1,
):
    """
    Basic test of the dumps function
    """
    mock_hvac_client_read.return_value = gen_vault_response_kv1(
        pwd_key="password")

    input_config = gen_input_config()
    input_config["vault_secrets"]["acme.pwd"] = "secret/acme/server/user.password"

    localhost_client.dumps(input_config)

    mock_hvac_client_read.assert_called_with(
        gen_input_config()["vault_secrets"]["acme.user"]
    )
    mock_dumps.assert_called_with(gen_processed_config())


@patch("vault_anyconfig.vault_anyconfig.load_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_load(
    mock_hvac_client_read,
    mock_load,
    localhost_client,
    gen_input_config,
    gen_processed_config,
    gen_vault_response_kv1,
):
    """
    Basic test of the load function
    """
    mock_hvac_client_read.return_value = gen_vault_response_kv1()
    mock_load.return_value = gen_input_config()

    assert localhost_client.load("in.json") == gen_processed_config()

    mock_hvac_client_read.assert_called_with(
        gen_input_config()["vault_secrets"]["acme.user"]
    )
    mock_load.assert_called_with("in.json")


@patch("vault_anyconfig.vault_anyconfig.load_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_load_invalid_response(
    mock_hvac_client_read,
    mock_load,
    localhost_client,
    gen_input_config,
    gen_processed_config,
    gen_vault_response_kv2,
):
    """
    Basic test of the load function with invalid vault response
    """
    mock_hvac_client_read.return_value = {"invalid_data": {}}
    mock_load.return_value = gen_input_config()

    with pytest.raises(RuntimeError):
        localhost_client.load("in.json")

    mock_hvac_client_read.assert_called_with(
        gen_input_config()["vault_secrets"]["acme.user"]
    )
    mock_load.assert_called_with("in.json")


@patch("vault_anyconfig.vault_anyconfig.load_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_load_kv2(
    mock_hvac_client_read,
    mock_load,
    localhost_client,
    gen_input_config,
    gen_processed_config,
    gen_vault_response_kv2,
):
    """
    Basic test of the load function
    """
    mock_hvac_client_read.return_value = gen_vault_response_kv2()
    mock_load.return_value = gen_input_config()

    assert localhost_client.load("in.json") == gen_processed_config()

    mock_hvac_client_read.assert_called_with(
        gen_input_config()["vault_secrets"]["acme.user"]
    )
    mock_load.assert_called_with("in.json")


@patch("vault_anyconfig.vault_anyconfig.load_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_load_different_vault_key(
    mock_hvac_client_read,
    mock_load,
    localhost_client,
    gen_input_config,
    gen_processed_config,
    gen_vault_response_kv1,
):
    """
    Tests that a Vault entry with a different key than the configuration dictionary maps correctly
    """
    mock_hvac_client_read.return_value = gen_vault_response_kv1()
    mock_load.return_value = gen_input_config()

    assert localhost_client.load("in.json") == gen_processed_config()

    mock_hvac_client_read.assert_called_with(
        gen_input_config()["vault_secrets"]["acme.user"]
    )
    mock_load.assert_called_with("in.json")


@patch("vault_anyconfig.vault_anyconfig.loads_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_loads(
    mock_hvac_client_read,
    mock_loads,
    localhost_client,
    gen_input_config,
    gen_vault_response_kv1,
):
    """
    Basic test of the loads function
    """
    mock_hvac_client_read.return_value = gen_vault_response_kv1()
    mock_loads.return_value = gen_input_config()
    input_config_json = jdumps(gen_input_config())
    localhost_client.loads(input_config_json)

    mock_hvac_client_read.assert_called_with(
        gen_input_config()["vault_secrets"]["acme.user"]
    )
    mock_loads.assert_called_with(input_config_json)


@patch("vault_anyconfig.vault_anyconfig.load_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_empty_path_list(
    mock_hvac_client_read,
    mock_load,
    localhost_client,
    gen_input_config,
    gen_vault_response_kv1,
):
    """
    Tests behavior when an empty key is used in the configuration dictionary
    """
    mock_hvac_client_read.return_value = gen_vault_response_kv1()
    mock_load.return_value = gen_input_config(
        vault_secrets={"": "some_secret"})

    with pytest.raises(RuntimeError):
        localhost_client.load("in.json")

    mock_hvac_client_read.assert_called_with("some_secret")
    mock_load.assert_called_with("in.json")


@patch("vault_anyconfig.vault_anyconfig.load_base")
def test_no_vault_secrets(mock_load, localhost_client, gen_input_config):
    """
    Test the client when there is no Vault configuration performed, but there is a empty vault_secrets section in the configuration file
    """
    mock_load.return_value = gen_input_config(vault_secrets={})

    localhost_client.load("in.json")

    mock_load.assert_called_with("in.json")


@patch("vault_anyconfig.vault_anyconfig.load_base")
def test_load_no_vault_with_secrets(mock_load, gen_input_config):
    """
    Basic test of the load function
    """
    mock_load.return_value = gen_input_config()

    input_config_edited = gen_input_config()
    del input_config_edited["vault_secrets"]

    client = VaultAnyConfig()

    with pytest.warns(UserWarning):
        assert client.load("in.json") == input_config_edited

    mock_load.assert_called_with("in.json")
