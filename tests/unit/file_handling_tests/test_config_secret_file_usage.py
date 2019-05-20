from unittest.mock import patch, mock_open, call, Mock
from pytest import fixture, warns
from copy import deepcopy
from json import dumps as jdumps
from stat import S_IRUSR, S_IWUSR
from os.path import abspath

from vault_anyconfig.vault_anyconfig import VaultAnyConfig


@patch("vault_anyconfig.vault_anyconfig.chmod")
@patch("builtins.open", new_callable=mock_open)
@patch("vault_anyconfig.vault_anyconfig.dump_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_dump(
    mock_hvac_client_read,
    mock_dump,
    mock_open_handle,
    mock_chmod,
    localhost_client,
    gen_input_config,
    gen_processed_config,
    gen_vault_response_kv1,
    file_path,
    file_path_normalized,
    file_contents,
    secret_path,
):
    """
    Basic test of the dump function with secret file writing
    """
    mock_hvac_client_read.return_value = gen_vault_response_kv1()

    localhost_client.dump(gen_input_config(), "out.json",
                          process_secret_files=True)

    mock_dump.assert_called_once_with(gen_input_config(), "out.json")

    mock_hvac_client_read.assert_called_once_with(secret_path)

    mock_open_handle.assert_called_once_with(file_path_normalized, "w")
    mock_open_handle().write.assert_called_once_with(file_contents)

    mock_chmod.assert_called_once_with(file_path_normalized, S_IRUSR)


@patch("vault_anyconfig.vault_anyconfig.chmod")
@patch("builtins.open", new_callable=mock_open)
@patch("vault_anyconfig.vault_anyconfig.dumps_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_dumps(
    mock_hvac_client_read,
    mock_dumps,
    mock_open_handle,
    mock_chmod,
    localhost_client,
    gen_input_config,
    gen_processed_config,
    gen_vault_response_kv1,
    file_path,
    file_path_normalized,
    file_contents,
    secret_path,
):
    """
    Basic test of the dumps function with secret file writing
    """
    mock_hvac_client_read.return_value = gen_vault_response_kv1()

    localhost_client.dumps(gen_input_config(), process_secret_files=True)

    mock_dumps.assert_called_once_with(gen_input_config())

    mock_hvac_client_read.assert_called_once_with(secret_path)

    mock_open_handle.assert_called_once_with(file_path_normalized, "w")
    mock_open_handle().write.assert_called_once_with(file_contents)

    mock_chmod.assert_called_once_with(file_path_normalized, S_IRUSR)


@patch("vault_anyconfig.vault_anyconfig.chmod")
@patch("builtins.open", new_callable=mock_open)
@patch("vault_anyconfig.vault_anyconfig.load_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_load(
    mock_hvac_client_read,
    mock_load,
    mock_open_handle,
    mock_chmod,
    localhost_client,
    gen_input_config,
    gen_processed_config,
    gen_vault_response_kv1,
    file_path,
    file_path_normalized,
    file_contents,
    secret_path,
):
    """
    Basic test of the load function with file writing
    """
    mock_load.return_value = gen_input_config()
    mock_hvac_client_read.return_value = gen_vault_response_kv1()

    assert (
        localhost_client.load("in.json", process_secret_files=True)
        == gen_processed_config()
    )

    mock_load.assert_called_once_with("in.json")

    mock_hvac_client_read.assert_called_once_with(secret_path)

    mock_open_handle.assert_called_once_with(file_path_normalized, "w")
    mock_open_handle().write.assert_called_once_with(file_contents)

    mock_chmod.assert_called_once_with(file_path_normalized, S_IRUSR)


@patch("vault_anyconfig.vault_anyconfig.chmod")
@patch("builtins.open", new_callable=mock_open)
@patch("vault_anyconfig.vault_anyconfig.loads_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_loads(
    mock_hvac_client_read,
    mock_loads,
    mock_open_handle,
    mock_chmod,
    localhost_client,
    gen_input_config,
    gen_processed_config,
    gen_vault_response_kv1,
    file_path,
    file_path_normalized,
    file_contents,
    secret_path,
):
    """
    Basic test of the loads function with file writing
    """
    mock_loads.return_value = gen_input_config()
    mock_hvac_client_read.return_value = gen_vault_response_kv1()
    input_config_json = jdumps(gen_input_config())

    assert (
        localhost_client.loads(input_config_json, process_secret_files=True)
        == gen_processed_config()
    )

    mock_loads.assert_called_once_with(jdumps(gen_input_config()))

    mock_hvac_client_read.assert_called_once_with(secret_path)

    mock_open_handle.assert_called_once_with(file_path_normalized, "w")
    mock_open_handle().write.assert_called_once_with(file_contents)

    mock_chmod.assert_called_once_with(file_path_normalized, S_IRUSR)


@patch("vault_anyconfig.vault_anyconfig.chmod")
@patch("builtins.open", new_callable=mock_open)
@patch("vault_anyconfig.vault_anyconfig.dump_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_dump_config_file_reference(
    mock_hvac_client_read,
    mock_dump,
    mock_open_handle,
    mock_chmod,
    localhost_client,
    gen_input_config,
    gen_processed_config,
    gen_vault_response_kv1,
    file_path,
    file_path_normalized,
    file_contents,
    secret_path,
):
    """
    Tests that the vault_files section can reference a file specified in the configuration
    """
    by_ref_file_path = "acme.cert_path"
    input_config = gen_input_config({by_ref_file_path: secret_path})

    mock_hvac_client_read.return_value = gen_vault_response_kv1()

    localhost_client.dump(input_config, "out.json", process_secret_files=True)

    mock_hvac_client_read.assert_called_once_with(secret_path)

    mock_open_handle.assert_called_once_with(file_path_normalized, "w")
    mock_open_handle().write.assert_called_once_with(file_contents)

    mock_chmod.assert_called_once_with(file_path_normalized, S_IRUSR)


@patch("vault_anyconfig.vault_anyconfig.dump_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_dump_disable_vault_files(
    mock_hvac_client_read,
    mock_dump,
    localhost_client,
    gen_vault_response_kv1,
    gen_input_config,
):
    """
    Ensure when process_secret_files is set to false, mock_hvac_client is never called (and thus the code for writing files was not triggered)
    """
    mock_hvac_client_read.return_value = gen_input_config()

    localhost_client.dump(gen_input_config(), "out.json",
                          process_secret_files=False)

    mock_hvac_client_read.assert_not_called()
    mock_dump.assert_called_with(gen_input_config(), "out.json")


@patch("vault_anyconfig.vault_anyconfig.dumps_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_dumps_disable_vault_files(
    mock_hvac_client_read, mock_dumps, localhost_client, gen_input_config
):
    """
    Ensure when process_secret_files is set to false, mock_hvac_client is never called (and thus the code for writing files was not triggered)
    """

    localhost_client.dumps(gen_input_config(), process_secret_files=False)

    mock_hvac_client_read.assert_not_called()
    mock_dumps.assert_called_with(gen_input_config())


@patch("vault_anyconfig.vault_anyconfig.load_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_load_disable_vault_files(
    mock_hvac_client_read,
    mock_load,
    localhost_client,
    gen_input_config,
    gen_processed_config,
):
    """
    Ensure when process_secret_files is set to false, mock_hvac_client is never called (and thus the code for writing files was not triggered)
    """
    mock_load.return_value = gen_input_config()

    assert (
        localhost_client.load("in.json", process_secret_files=False)
        == gen_processed_config()
    )

    mock_hvac_client_read.assert_not_called()
    mock_load.assert_called_with("in.json")


@patch("vault_anyconfig.vault_anyconfig.loads_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_loads_disable_vault_files(
    mock_hvac_client_read, mock_loads, localhost_client, gen_input_config
):
    """
    Ensure when process_secret_files is set to false, mock_hvac_client is never called (and thus the code for writing files was not triggered)
    """
    mock_loads.return_value = gen_input_config()
    string_raw_config = jdumps(gen_input_config())
    localhost_client.loads(string_raw_config, process_secret_files=False)

    mock_hvac_client_read.assert_not_called()
    mock_loads.assert_called_with(string_raw_config)


@patch("vault_anyconfig.vault_anyconfig.chmod")
@patch("builtins.open", new_callable=mock_open)
@patch("vault_anyconfig.vault_anyconfig.dump_base")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_dump_passthrough(
    mock_hvac_client_read,
    mock_dump,
    mock_open_handle,
    mock_chmod,
    localhost_client,
    gen_input_config,
    gen_processed_config,
    gen_vault_response_kv1,
    file_path,
    file_path_normalized,
    file_contents,
    secret_path,
):
    """
    Tests a warning is thrown where there are files specified but the passthrough flag is set.
    """
    mock_hvac_client_read.return_value = gen_vault_response_kv1()

    with warns(UserWarning):
        VaultAnyConfig().dump(gen_input_config(), "out.json", process_secret_files=True)

    mock_dump.assert_called_once_with(gen_input_config(), "out.json")
    mock_hvac_client_read.assert_not_called()
    mock_open_handle.assert_not_called()
    mock_chmod.assert_not_called()
