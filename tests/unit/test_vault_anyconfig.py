"""
Tests for the vault_anyconfig package.
"""
#pylint: disable=attribute-defined-outside-init
#pylint: disable=too-few-public-methods
#pylint: disable=no-self-use
#pylint: disable=unused-argument
from unittest.mock import patch
from copy import deepcopy
from json import dumps as jdumps

import pytest

from vault_anyconfig.vault_anyconfig import VaultAnyConfig

class TestConfigInit:
    """
    Tests for the init function
    """
    vault_config = {
        "vault_config": {
            "url": "http://localhost",
        }
    }

    empty_vault_config = {
        "vault_config": {}
    }

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

class TestConfig:
    """
    Parent class performing basic setup of the client
    """
    @patch("vault_anyconfig.vault_anyconfig.Client.__init__")
    def setup(self, mock_hvac_client):
        """
        Configures a mock instance of the HVAC client
        """
        self.client = VaultAnyConfig(url="http://localhost")

class TestConfigAuth(TestConfig):
    """
    Tests for the auth convenience method
    """
    vault_creds = {
        "vault_creds": {
            "role_id": "test-role-id",
            "secret_id": "test-secret-id",
            "auth_method": "approle"
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
        mock_auth_approle.assert_called_with(role_id=self.vault_creds["vault_creds"]["role_id"], secret_id=self.vault_creds["vault_creds"]["secret_id"])
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

class TestConfigAccess(TestConfig):
    """
    Tests for the load(s) and dump(s) functions
    """
    raw_config = {
        "acme": {
            "host": "https://acme.com",
            "cert_path": "/secret/cert"
        },
        "vault_secrets": {
            "acme.user": "secret/acme/server/user",
            "acme.pwd": "secret/acme/server/user"
        }
    }

    processed_config = {
        "acme": {
            "host": raw_config["acme"]["host"],
            "cert_path": raw_config["acme"]["cert_path"],
            "user": "test_user",
            "pwd": "test_password"
        }
    }

    vault_response = {
        "data": {
            "user": processed_config["acme"]["user"],
            "pwd": processed_config["acme"]["pwd"]
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

        mock_hvac_client_read.assert_called_with(self.raw_config["vault_secrets"]["acme.user"])
        mock_dump.assert_called_with(self.processed_config, "out.json")

    @patch("vault_anyconfig.vault_anyconfig.dumps_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_dumps(self, mock_hvac_client_read, mock_dumps):
        """
        Basic test of the dumps function
        """
        mock_hvac_client_read.return_value = self.vault_response

        raw_config = deepcopy(self.raw_config)

        self.client.dumps(raw_config)

        mock_hvac_client_read.assert_called_with(self.raw_config["vault_secrets"]["acme.user"])
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

        mock_hvac_client_read.assert_called_with(self.raw_config["vault_secrets"]["acme.user"])
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

        mock_hvac_client_read.assert_called_with(self.raw_config["vault_secrets"]["acme.user"])
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
