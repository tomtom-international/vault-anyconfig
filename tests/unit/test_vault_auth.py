"""
Tests for the auth convenience method
"""

from unittest.mock import patch, mock_open, call, Mock
from json import dumps as jdumps
from stat import S_IRUSR, S_IWUSR

import pytest

from vault_anyconfig.vault_anyconfig import VaultAnyConfig


@pytest.fixture
def gen_vault_creds():
    """
    Generates sample vault credentials for use in tests
    """

    def _gen_vault_creds():
        vault_creds = {
            "vault_creds": {"role_id": "test-role-id", "secret_id": "test-secret-id", "auth_method": "approle"}
        }
        return vault_creds

    return _gen_vault_creds


@patch("vault_anyconfig.vault_anyconfig.Client.is_authenticated")
@patch("vault_anyconfig.vault_anyconfig.Client.auth_approle")
@patch("vault_anyconfig.vault_anyconfig.loads_base")
def test_auto_auth(mock_load, mock_auth_approle, mock_is_authenticated, localhost_client, gen_vault_creds):
    """
    Basic test for the auto_auth function
    """
    mock_load.return_value = gen_vault_creds()
    mock_is_authenticated.return_value = False

    localhost_client.auto_auth("config.json", ac_parser="test_parser")

    compare_vault_creds = gen_vault_creds()

    mock_load.assert_called_with("config.json", ac_parser="test_parser")
    mock_auth_approle.assert_called_with(
        role_id=compare_vault_creds["vault_creds"]["role_id"], secret_id=compare_vault_creds["vault_creds"]["secret_id"]
    )
    mock_is_authenticated.assert_called_with()


@patch("vault_anyconfig.vault_anyconfig.Client.is_authenticated")
@patch("vault_anyconfig.vault_anyconfig.loads_base")
def test_auto_auth_bad_method(mock_load, mock_is_authenticated, localhost_client, gen_vault_creds):
    """
    Test that the exception is thrown as expected when using a bad authentication method
    """
    local_vault_creds = gen_vault_creds()
    local_vault_creds["vault_creds"]["auth_method"] = "nothing"
    mock_load.return_value = local_vault_creds
    mock_is_authenticated.return_value = False

    with pytest.raises(NotImplementedError):
        localhost_client.auto_auth("config.json", ac_parser="test_parser")

    mock_load.assert_called_with("config.json", ac_parser="test_parser")


AWS_IAM_VAULT_CREDS = [
    {"access_key": "test_access_key", "secret_key": "test_secret_key", "session_token": "test_session_token"},
    {"access_key": "test_access_key", "secret_key": "test_secret_key"},
]


@pytest.mark.parametrize("vault_creds", AWS_IAM_VAULT_CREDS)
@patch("vault_anyconfig.vault_anyconfig.Client.auth_aws_iam")
@patch("vault_anyconfig.vault_anyconfig.Client.is_authenticated")
@patch("vault_anyconfig.vault_anyconfig.loads_base")
def test_auto_auth_aws_iam_method(mock_load, mock_is_authenticated, mock_auth_aws_iam, vault_creds, localhost_client):
    """
    Test that the aws_iam method *with* hardcoded aws creds is called directly
    """
    local_vault_creds = {"vault_creds": {"auth_method": "aws_iam", "role": "test_role"}}
    local_vault_creds["vault_creds"].update(vault_creds)

    mock_load.return_value = local_vault_creds
    mock_is_authenticated.return_value = False

    localhost_client.auto_auth("config.json", ac_parser="test_parser")
    mock_load.assert_called_with("config.json", ac_parser="test_parser")
    mock_auth_aws_iam.assert_called_with(**vault_creds, role="test_role")


@pytest.mark.parametrize("vault_creds", AWS_IAM_VAULT_CREDS)
@patch("boto3.Session.get_credentials")
@patch("vault_anyconfig.vault_anyconfig.Client.auth_aws_iam")
@patch("vault_anyconfig.vault_anyconfig.Client.is_authenticated")
@patch("vault_anyconfig.vault_anyconfig.loads_base")
def test_auto_auth_aws_iam_method_role_only(
    mock_load, mock_is_authenticated, mock_auth_aws_iam, mock_get_credentials, vault_creds, localhost_client
):
    """
    Test that the aws_iam method *with only* hardcoded aws creds pulls creds
    from AWS SDK defaults
    """
    local_vault_creds = {"vault_creds": {"auth_method": "aws_iam", "role": "test_role"}}
    mock_load.return_value = local_vault_creds

    # we're mocking botocore.credentials.Credentials which uses `token` not `session_token`
    local_boto_creds = Mock(
        access_key=vault_creds["access_key"],
        secret_key=vault_creds["secret_key"],
        token=vault_creds.get("session_token", None),
    )
    mock_get_credentials.return_value = local_boto_creds

    mock_is_authenticated.return_value = False

    localhost_client.auto_auth("config.json", ac_parser="test_parser")
    mock_load.assert_called_with("config.json", ac_parser="test_parser")
    mock_auth_aws_iam.assert_called_with(**vault_creds, role="test_role")


@patch("vault_anyconfig.vault_anyconfig.Client.auth_kubernetes")
@patch("vault_anyconfig.vault_anyconfig.Client.is_authenticated")
@patch("vault_anyconfig.vault_anyconfig.loads_base")
def test_auto_auth_k8s_method(mock_load, mock_is_authenticated, mock_auth_kubernetes, localhost_client):
    """
    Test that the kubernetes method *without* the token path configured is called directly
    """
    local_vault_creds = {"vault_creds": {"auth_method": "kubernetes", "role": "test_role", "jwt": "jwt_string"}}
    mock_load.return_value = local_vault_creds
    mock_is_authenticated.return_value = False

    localhost_client.auto_auth("config.json", ac_parser="test_parser")

    mock_load.assert_called_with("config.json", ac_parser="test_parser")
    mock_auth_kubernetes.assert_called_with(role="test_role", jwt="jwt_string")


@patch("vault_anyconfig.vault_anyconfig.isfile")
@patch("vault_anyconfig.vault_anyconfig.Client.auth_kubernetes")
@patch("vault_anyconfig.vault_anyconfig.Client.is_authenticated")
@patch("vault_anyconfig.vault_anyconfig.load_base")
def test_auto_auth_k8s_method_token_path(
    mock_load, mock_is_authenticated, mock_auth_kubernetes, mock_isfile, localhost_client
):
    """
    Test that the kubernetes method *with* the token path configured is called with the value from the token file
    """
    mock_isfile.return_value = True
    local_vault_creds = {
        "vault_creds": {
            "auth_method": "kubernetes",
            "role": "test_role",
            "token_path": "/var/run/secrets/kubernetes.io/serviceaccount",
        }
    }
    mock_load.return_value = local_vault_creds
    mock_is_authenticated.return_value = False

    with patch("builtins.open", mock_open(read_data="jwt_string")) as mock_open_handle:
        localhost_client.auto_auth("config.json")
        mock_open_handle.assert_called_once_with("/var/run/secrets/kubernetes.io/serviceaccount", "r")

    mock_load.assert_called_with("config.json", ac_parser=None)
    mock_auth_kubernetes.assert_called_with(role="test_role", jwt="jwt_string")


def test_auth_with_passthrough():
    """
    Tests that the auto_auth will simply be bypassed when using an instance with passthrough
    """
    client = VaultAnyConfig()
    assert client.auto_auth("config.json")


@patch("vault_anyconfig.vault_anyconfig.load_base")
@patch("vault_anyconfig.vault_anyconfig.Client.is_authenticated")
def test_auth_with_already_authenticated(mock_is_authenticated, mock_load, gen_vault_creds, localhost_client):
    """
    Tests that the auto_auth will simply be bypassed when the client is already authenticated
    """
    mock_load.return_value = gen_vault_creds()
    mock_is_authenticated.return_value = True

    assert localhost_client.auto_auth("config.json")


@patch("vault_anyconfig.vault_anyconfig.Client.is_authenticated")
def test_auth_with_already_authenticated_and_passthrough(mock_is_authenticated):
    """
    Tests that the auto_auth will simply be bypassed when using an instance with passthrough set and the client is already authenticated
    """
    mock_is_authenticated.return_value = True
    client = VaultAnyConfig()
    assert client.auto_auth("config.json")


@patch("vault_anyconfig.vault_anyconfig.VaultAnyConfig.auto_auth")
def test_auth_from_file(mock_auto_auth):
    """
    Tests that auth_from_file calls auto_auth
    """
    client = VaultAnyConfig()
    client.auth_from_file("test.json")
    mock_auto_auth.assert_called_once_with("test.json", ac_parser=None)
