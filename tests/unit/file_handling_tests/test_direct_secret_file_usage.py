"""
Tests for the secret file writing functionality in vault_anyconfig package.
"""

from unittest.mock import patch, mock_open, call, Mock
from stat import S_IRUSR, S_IWUSR


from pytest import fixture, warns


from vault_anyconfig.vault_anyconfig import VaultAnyConfig


@patch("vault_anyconfig.vault_anyconfig.chmod")
@patch("builtins.open", new_callable=mock_open)
@patch("vault_anyconfig.vault_anyconfig.isfile")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_write_existing_file(
    mock_hvac_client_read,
    mock_isfile,
    mock_open_handle,
    mock_chmod,
    localhost_client,
    file_contents,
    file_path,
    file_path_normalized,
    secret_path,
):
    """
    Tests that chmod is called twice if the secret file already existed on disk
    """
    mock_isfile.return_value = True
    mock_hvac_client_read.return_value = {"data": {"file": file_contents}}

    localhost_client.save_file_from_vault(file_path, secret_path, "file")

    mock_hvac_client_read.assert_called_once_with(secret_path)

    mock_open_handle.assert_called_once_with(file_path_normalized, "w")
    mock_open_handle().write.assert_called_once_with(file_contents)

    chmod_calls = [
        call(file_path_normalized, S_IWUSR),
        call(file_path_normalized, S_IRUSR),
    ]
    mock_chmod.assert_has_calls(chmod_calls, any_order=False)


@patch("vault_anyconfig.vault_anyconfig.chmod")
@patch("builtins.open", new_callable=mock_open)
@patch("vault_anyconfig.vault_anyconfig.isfile")
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_file_with_write_perm_fail(
    mock_hvac_client_read,
    mock_isfile,
    mock_open_handle,
    mock_chmod,
    localhost_client,
    file_contents,
    file_path,
    file_path_normalized,
    secret_path,
):
    """
    Tests that a warning is thrown if chmod is unable to set write permission on the secret file on disk
    """
    mock_isfile.return_value = True
    mock_hvac_client_read.return_value = {"data": {"file": file_contents}}

    mock_chmod.side_effect = PermissionError(Mock(return_value="IOError 13"))

    with warns(UserWarning):
        localhost_client.save_file_from_vault(file_path, secret_path, "file")

    mock_hvac_client_read.assert_called_once_with(secret_path)

    mock_open_handle.assert_called_once_with(file_path_normalized, "w")
    mock_open_handle().write.assert_called_once_with(file_contents)

    chmod_calls = [call(file_path_normalized, S_IWUSR)]
    mock_chmod.assert_has_calls(chmod_calls, any_order=False)


@patch("vault_anyconfig.vault_anyconfig.chmod")
@patch("builtins.open", new_callable=mock_open)
@patch("vault_anyconfig.vault_anyconfig.Client.read")
def test_file_with_read_perm_fail(
    mock_hvac_client_read,
    mock_open_handle,
    mock_chmod,
    localhost_client,
    file_path,
    file_path_normalized,
    secret_path,
    file_contents,
):

    """
    Tests that a warning is thrown if chmod is unable to set read-only permissions on a secret file on disk
    """
    mock_hvac_client_read.return_value = {"data": {"file": file_contents}}

    mock_chmod.side_effect = PermissionError(Mock(return_value="IOError 13"))

    with warns(UserWarning):
        localhost_client.save_file_from_vault(file_path, secret_path, "file")

    mock_hvac_client_read.assert_called_once_with(secret_path)

    mock_open_handle.assert_called_once_with(file_path_normalized, "w")
    mock_open_handle().write.assert_called_once_with(file_contents)

    chmod_calls = [call(file_path_normalized, S_IRUSR)]
    mock_chmod.assert_has_calls(chmod_calls, any_order=False)

