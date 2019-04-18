"""
Pytest configuration including fixtures
"""
from unittest.mock import patch
from pytest import fixture

from vault_anyconfig.vault_anyconfig import VaultAnyConfig


@fixture
@patch("vault_anyconfig.vault_anyconfig.Client.__init__")
def localhost_client(mock_hvac_client):
    """
    Configures a mock instance of the HVAC client
    """
    return VaultAnyConfig(url="http://localhost")
