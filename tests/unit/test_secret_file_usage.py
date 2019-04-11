"""
Tests for the secret file writing functionality in vault_anyconfig package.
"""
# pylint: disable=attribute-defined-outside-init
# pylint: disable=too-few-public-methods
# pylint: disable=no-self-use
# pylint: disable=unused-argument
from unittest.mock import patch, mock_open, call, Mock
from copy import deepcopy
from json import dumps as jdumps
from stat import S_IRUSR, S_IWUSR
from os.path import abspath

import pytest
from hypothesis import given, example
import hypothesis.strategies as strat

from vault_anyconfig.vault_anyconfig import VaultAnyConfig

from .test_config import TestConfig


class TestWriteFile(TestConfig):
    """
    Tests directly accessing the save_file_from_vault method
    """

    def setup(self):
        super().setup()
        self.file_contents = "secret_string_to_write"

        self.file_path = "/some/file/secret"
        self.file_path_normalized = abspath(self.file_path)
        self.secret_path = "/secret/acme/cert"

    @patch("vault_anyconfig.vault_anyconfig.chmod")
    @patch("builtins.open", new_callable=mock_open)
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_write_new_file(self, mock_hvac_client_read, mock_open_handle, mock_chmod):
        """
        Retrieves a string from a (mock) HVAC client and writes it to a (mock) file.
        """
        mock_hvac_client_read.return_value = {"data": {"file": self.file_contents}}

        self.client.save_file_from_vault(self.file_path, self.secret_path, "file")

        mock_hvac_client_read.assert_called_once_with(self.secret_path)

        mock_open_handle.assert_called_once_with(self.file_path_normalized, "w")
        mock_open_handle().write.assert_called_once_with(self.file_contents)

        mock_chmod.assert_called_once_with(self.file_path_normalized, S_IRUSR)

    @patch("vault_anyconfig.vault_anyconfig.chmod")
    @patch("builtins.open", new_callable=mock_open)
    @patch("vault_anyconfig.vault_anyconfig.isfile")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_write_existing_file(
        self, mock_hvac_client_read, mock_isfile, mock_open_handle, mock_chmod
    ):
        """
        Tests that chmod is called twice if the secret file already existed on disk
        """
        mock_isfile.return_value = True
        mock_hvac_client_read.return_value = {"data": {"file": self.file_contents}}

        self.client.save_file_from_vault(self.file_path, self.secret_path, "file")

        mock_hvac_client_read.assert_called_once_with(self.secret_path)

        mock_open_handle.assert_called_once_with(self.file_path_normalized, "w")
        mock_open_handle().write.assert_called_once_with(self.file_contents)

        chmod_calls = [
            call(self.file_path_normalized, S_IWUSR),
            call(self.file_path_normalized, S_IRUSR),
        ]
        mock_chmod.assert_has_calls(chmod_calls, any_order=False)

    @patch("vault_anyconfig.vault_anyconfig.chmod")
    @patch("builtins.open", new_callable=mock_open)
    @patch("vault_anyconfig.vault_anyconfig.isfile")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_file_with_write_perm_fail(
        self, mock_hvac_client_read, mock_isfile, mock_open_handle, mock_chmod
    ):
        """
        Tests that a warning is thrown if chmod is unable to set write permission on the secret file on disk
        """
        mock_isfile.return_value = True
        mock_hvac_client_read.return_value = {"data": {"file": self.file_contents}}

        mock_chmod.side_effect = PermissionError(Mock(return_value="IOError 13"))

        with pytest.warns(UserWarning):
            self.client.save_file_from_vault(self.file_path, self.secret_path, "file")

        mock_hvac_client_read.assert_called_once_with(self.secret_path)

        mock_open_handle.assert_called_once_with(self.file_path_normalized, "w")
        mock_open_handle().write.assert_called_once_with(self.file_contents)

        chmod_calls = [call(self.file_path_normalized, S_IWUSR)]
        mock_chmod.assert_has_calls(chmod_calls, any_order=False)

    @patch("vault_anyconfig.vault_anyconfig.chmod")
    @patch("builtins.open", new_callable=mock_open)
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_file_with_read_perm_fail(
        self, mock_hvac_client_read, mock_open_handle, mock_chmod
    ):
        """
        Tests that a warning is thrown if chmod is unable to set read-only permissions on a secret file on disk
        """
        mock_hvac_client_read.return_value = {"data": {"file": self.file_contents}}

        mock_chmod.side_effect = PermissionError(Mock(return_value="IOError 13"))

        with pytest.warns(UserWarning):
            self.client.save_file_from_vault(self.file_path, self.secret_path, "file")

        mock_hvac_client_read.assert_called_once_with(self.secret_path)

        mock_open_handle.assert_called_once_with(self.file_path_normalized, "w")
        mock_open_handle().write.assert_called_once_with(self.file_contents)

        chmod_calls = [call(self.file_path_normalized, S_IRUSR)]
        mock_chmod.assert_has_calls(chmod_calls, any_order=False)


class TestWriteFileFromConfigFile(TestConfig):
    def setup(self):
        super().setup()
        self.file_contents = "secret_string_to_write"

        self.file_path = "/some/file/secret"
        self.file_path_normalized = abspath(self.file_path)
        self.secret_path = "/secret/acme/cert"

        self.raw_config = {
            "acme": {"host": "https://acme.com", "cert_path": self.file_path},
            "vault_files": {self.file_path: self.secret_path},
        }

        self.processed_config = {
            "acme": {
                "host": self.raw_config["acme"]["host"],
                "cert_path": self.raw_config["acme"]["cert_path"],
            },
            "vault_files": {self.file_path: self.secret_path},
        }

        self.vault_response = {"data": {"file": self.file_contents}}

    @patch("vault_anyconfig.vault_anyconfig.chmod")
    @patch("builtins.open", new_callable=mock_open)
    @patch("vault_anyconfig.vault_anyconfig.dump_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_dump(self, mock_hvac_client_read, mock_dump, mock_open_handle, mock_chmod):
        """
        Basic test of the dump function
        """
        mock_hvac_client_read.return_value = self.vault_response

        raw_config = deepcopy(self.raw_config)

        self.client.dump(raw_config, "out.json")

        mock_hvac_client_read.assert_called_once_with(self.secret_path)

        mock_open_handle.assert_called_once_with(self.file_path_normalized, "w")
        mock_open_handle().write.assert_called_once_with(self.file_contents)

        mock_chmod.assert_called_once_with(self.file_path_normalized, S_IRUSR)

    @patch("vault_anyconfig.vault_anyconfig.chmod")
    @patch("builtins.open", new_callable=mock_open)
    @patch("vault_anyconfig.vault_anyconfig.dump_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_dump_config_file_reference(
        self, mock_hvac_client_read, mock_dump, mock_open_handle, mock_chmod
    ):
        """
        Tests that the vault_files section can reference a file specified in the configuration
        """
        by_ref_file_path = "acme.cert_path"
        self.raw_config["vault_files"] = {by_ref_file_path: self.secret_path}
        self.processed_config["vault_files"] = {by_ref_file_path: self.secret_path}

        mock_hvac_client_read.return_value = self.vault_response

        raw_config = deepcopy(self.raw_config)

        self.client.dump(raw_config, "out.json")

        mock_hvac_client_read.assert_called_once_with(self.secret_path)

        mock_open_handle.assert_called_once_with(self.file_path_normalized, "w")
        mock_open_handle().write.assert_called_once_with(self.file_contents)

        mock_chmod.assert_called_once_with(self.file_path_normalized, S_IRUSR)

    @patch("vault_anyconfig.vault_anyconfig.dump_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_dump_disable_vault_files(self, mock_hvac_client_read, mock_dump):
        """
        Ensure when process_secret_files is set to false, mock_hvac_client is never called (and thus the code for writing files was not triggered)
        """
        mock_hvac_client_read.return_value = self.vault_response

        raw_config = deepcopy(self.raw_config)

        self.client.dump(raw_config, "out.json", process_secret_files=False)

        mock_hvac_client_read.assert_not_called()
        mock_dump.assert_called_with(self.raw_config, "out.json")

    @patch("vault_anyconfig.vault_anyconfig.dumps_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_dumps_disable_vault_files(self, mock_hvac_client_read, mock_dumps):
        """
        Ensure when process_secret_files is set to false, mock_hvac_client is never called (and thus the code for writing files was not triggered)
        """
        raw_config = deepcopy(self.raw_config)

        self.client.dumps(raw_config, process_secret_files=False)

        mock_hvac_client_read.assert_not_called()
        mock_dumps.assert_called_with(self.raw_config)

    @patch("vault_anyconfig.vault_anyconfig.load_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_load_disable_vault_files(self, mock_hvac_client_read, mock_load):
        """
        Ensure when process_secret_files is set to false, mock_hvac_client is never called (and thus the code for writing files was not triggered)
        """
        mock_load.return_value = deepcopy(self.raw_config)

        assert (
            self.client.load("in.json", process_secret_files=False)
            == self.processed_config
        )

        mock_hvac_client_read.assert_not_called()
        mock_load.assert_called_with("in.json")

    @patch("vault_anyconfig.vault_anyconfig.loads_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    def test_loads_disable_vault_files(self, mock_hvac_client_read, mock_loads):
        """
        Ensure when process_secret_files is set to false, mock_hvac_client is never called (and thus the code for writing files was not triggered)
        """
        mock_loads.return_value = deepcopy(self.raw_config)
        string_raw_config = jdumps(self.raw_config)
        self.client.loads(string_raw_config, process_secret_files=False)

        mock_hvac_client_read.assert_not_called()
        mock_loads.assert_called_with(string_raw_config)


class TestFileWritingFuzzing(TestConfig):
    def setup(self):
        super().setup()
        self.file_contents = "secret_string_to_write"

        self.file_path = "/some/file/secret"
        self.file_path_normalized = abspath(self.file_path)
        self.secret_path = "/secret/acme/cert"

        self.raw_config = {
            "acme": {"host": "https://acme.com", "cert_path": self.file_path},
            "vault_files": {},
        }

        self.processed_config = {
            "acme": {
                "host": self.raw_config["acme"]["host"],
                "cert_path": self.raw_config["acme"]["cert_path"],
            },
            "vault_files": {},
        }

        self.vault_response = {"data": {"file": self.file_contents}}

    @patch("vault_anyconfig.vault_anyconfig.chmod")
    @patch("vault_anyconfig.vault_anyconfig.dump_base")
    @patch("vault_anyconfig.vault_anyconfig.Client.read")
    @given(
        strat.text(min_size=1, alphabet=strat.characters(blacklist_categories=("C"))),
        strat.text(min_size=1, alphabet=strat.characters(blacklist_categories=("C"))),
        strat.text(),
    )
    @example(
        file_path="/some/path/secret.cert", secret_path="/secret/file", secret_key="crt"
    )
    @example(
        file_path="/some/path/.hiddenfile",
        secret_path="/secret/hidden/file",
        secret_key="",
    )
    @example(file_path=".hiddenfile", secret_path="/secret/hidden/file", secret_key="")
    @example(
        file_path=" .hiddenfile_with_space",
        secret_path="/secret/hidden/file",
        secret_key="",
    )
    @example(
        file_path=".hiddenfile_with_space ",
        secret_path="/secret/hidden/file",
        secret_key="",
    )
    @example(file_path="somefile", secret_path="/secret/file", secret_key="")
    @example(file_path="somefile", secret_path=" /secret/with/space", secret_key="")
    @example(file_path="somefile", secret_path="/secret/with/space ", secret_key="")
    @example(file_path="0", secret_path=".", secret_key="")
    def test_dump_different_file_paths_and_secrets(
        self,
        mock_hvac_client_read,
        mock_dump,
        mock_chmod,
        file_path,
        secret_path,
        secret_key,
    ):
        """
        Tests that secret keys, whitespace in paths, and hidden files are all handled correctly
        """

        raw_config = deepcopy(self.raw_config)
        processed_config = deepcopy(self.processed_config)
        vault_response = deepcopy(self.vault_response)

        if secret_key != "":
            vault_response = {"data": {secret_key: self.file_contents}}
            secret_key = "." + secret_key
        else:
            vault_response = {"data": {"file": self.file_contents}}

        raw_config["vault_files"][file_path] = secret_path + secret_key
        processed_config["vault_files"][file_path] = secret_path + secret_key

        mock_hvac_client_read.return_value = vault_response

        with patch("builtins.open", new_callable=mock_open) as mock_open_handle:
            local_raw_config = deepcopy(raw_config)
            self.client.dump(local_raw_config, "out.json")
            mock_open_handle.assert_called_once_with(abspath(file_path), "w")
            mock_open_handle().write.assert_called_once_with(self.file_contents)

        mock_hvac_client_read.assert_called_with(secret_path)

        mock_chmod.assert_called_with(abspath(file_path), S_IRUSR)
