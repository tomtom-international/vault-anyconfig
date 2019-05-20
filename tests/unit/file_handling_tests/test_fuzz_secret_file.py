from unittest.mock import patch, mock_open, call, Mock
from copy import deepcopy
from json import dumps as jdumps
from stat import S_IRUSR, S_IWUSR
from os.path import abspath

import pytest
from hypothesis import given, example
import hypothesis.strategies as strat

from vault_anyconfig.vault_anyconfig import VaultAnyConfig


@patch("vault_anyconfig.vault_anyconfig.chmod")
@patch("vault_anyconfig.vault_anyconfig.dump_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
@given(
    file_path=strat.text(
        min_size=1, alphabet=strat.characters(blacklist_categories=("C"))
    ),
    secret_path=strat.text(
        min_size=1,
        alphabet=strat.characters(
            blacklist_categories=("C"), # Since we separately specify the key, we cannot include "." in the secret path
            blacklist_characters=".",
        ),
    ),
    secret_key=strat.text(
        min_size=1,
        alphabet=strat.characters(
            blacklist_categories=("C"),
            blacklist_characters=".",  # Keys require actual values, not more dot separators
        ),
    ),
)
@example(
    file_path="/some/path/secret.cert", secret_path="/secret/file", secret_key="crt"
)
@example(
    file_path="/some/path/.hiddenfile", secret_path="/secret/hidden/file", secret_key=""
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
def test_dump_different_file_paths_and_secrets(
    mock_hvac_client_read,
    mock_dump,
    mock_chmod,
    file_path,
    secret_path,
    secret_key,
    localhost_client,
    gen_input_config,
    gen_processed_config,
    gen_vault_response_kv1,
    file_contents,
):
    """
    Tests that secret keys, whitespace in paths, and hidden files are all handled correctly
    """
    mock_hvac_client_read.return_value = gen_vault_response_kv1(
        file_contents=file_contents, secret_key=secret_key
    )

    if secret_key != "":
        secret_key = "." + secret_key

    input_config = gen_input_config(
        vault_files={file_path: secret_path + secret_key})

    with patch("builtins.open", new_callable=mock_open) as mock_open_handle:
        localhost_client.dump(input_config, "out.json",
                              process_secret_files=True)
        mock_open_handle.assert_called_once_with(abspath(file_path), "w")
        mock_open_handle().write.assert_called_once_with(file_contents)

    mock_hvac_client_read.assert_called_with(secret_path)

    mock_chmod.assert_called_with(abspath(file_path), S_IRUSR)


@patch("vault_anyconfig.vault_anyconfig.chmod")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
@given(
    file_path=strat.text(
        min_size=1, alphabet=strat.characters(blacklist_categories=("C"))
    ),
    secret_path=strat.text(
        min_size=1, alphabet=strat.characters(blacklist_categories=("C"))
    ),
    secret_key=strat.text(),
)
def test_write_new_file(
    mock_hvac_client_read,
    mock_chmod,
    file_path,
    secret_path,
    secret_key,
    localhost_client,
    file_contents,
):
    """
    Retrieves a string from a (mock) HVAC client and writes it to a (mock) file.
    """
    mock_hvac_client_read.return_value = {"data": {"file": file_contents}}
    file_path_normalized = abspath(file_path)

    with patch("builtins.open", new_callable=mock_open) as mock_open_handle:
        localhost_client.save_file_from_vault(file_path, secret_path, "file")
        mock_open_handle.assert_called_once_with(file_path_normalized, "w")
        mock_open_handle().write.assert_called_once_with(file_contents)

    mock_hvac_client_read.assert_called_with(secret_path)

    mock_chmod.assert_called_with(file_path_normalized, S_IRUSR)
