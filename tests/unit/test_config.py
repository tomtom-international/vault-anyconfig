"""
Base class for test classes to inherit from, provides a preconfigured mock Vault client
"""
from unittest.mock import patch

from vault_anyconfig.vault_anyconfig import VaultAnyConfig


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
