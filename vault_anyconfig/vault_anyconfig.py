"""
Provides an extension to the HVAC Hashicorp Vault client for reading and writing configuration files.
"""
from warnings import warn

from hvac import Client
from anyconfig import dump as dump_base, dumps as dumps_base, load as load_base, loads as loads_base, merge

class VaultAnyConfig(Client):
    """
    Extends the HVAC Hashicorp Vault client to be able to read/write configuration files and update them with information from a Vault instance.
    """
    def __init__(self, vault_config_file=None, **args):
        """
        Creates a connection to Vault with either the arguments normally provided to an HVAC client instance, or a configuration file containing them.
        See https://github.com/hvac/hvac/blob/master/hvac/v1/__init__.py for detailed list of arguments available.
        The Vault configuration must be within a dictionary named "vault_config" and each element's name must match the names of the parameters being
        used on the HVAC Client's init function.
        Args:
            - vault_config_file: [Optional] file[path] to a configuration file with Vault configuration arguments
            - args: [Optional] Arguments for an HVAC client, typically it will need at least url
        """
        self.pass_through_flag = False

        if not vault_config_file:
            vault_config = args
        else:
            vault_config = load_base(vault_config_file).get('vault_config', {})

        if vault_config:
            super().__init__(**vault_config)
        else:
            self.pass_through_flag = True

    def auth_from_file(self, vault_creds_file):
        """
        Invokes the specified Vault authentication method and provides credentials to it from a configuration file
        See https://hvac.readthedocs.io/en/latest/usage/auth_methods/index.html for a list of HVAC auth methods.
        The Vault credentials must be within a dictionary named "vault_creds" and each element's name must match the names of the parameters of the
        desired auth function. It must also contain a "auth_method" member that matches one of the authentication methods in HVAC
        Args:
            - vault_creds_file: file containing the credentials for the Vault
        Returns:
            bool of authenication status
        """
        if self.pass_through_flag:
            return True

        creds = load_base(vault_creds_file)['vault_creds']
        auth_method = "auth_" + creds['auth_method']
        creds.pop('auth_method', None)

        try:
            method = getattr(self, auth_method)
        except AttributeError:
            raise NotImplementedError("HVAC does not provide {} as an authentication method".format(auth_method))

        method(**creds)
        return self.is_authenticated()

    def dump(self, data, out, **args):
        """
        First updates the provided dictionary with keys from the Vault, then calls anyconfig to dump out a configuration file.
        See https://python-anyconfig.readthedocs.io/en/latest/api/anyconfig.api.html#anyconfig.api.dump for detailed invocation options.
        Args:
            data: configuration dict
            out: file[path] (or file-like) object to write to
        """
        updated_data = self.__process_vault_keys(data)
        dump_base(updated_data, out, **args)

    def dumps(self, data, **args):
        """
        First updates the provided dictionary with keys from the Vault, then calls anyconfig to dump out string
        See https://python-anyconfig.readthedocs.io/en/latest/api/anyconfig.api.html#anyconfig.api.dump for detailed invocation options.
        Args:
            data: configuration dict
        Returns:
            String with the configuration
        """
        updated_data = self.__process_vault_keys(data)
        return dumps_base(updated_data, **args)

    def load(self, path_spec, **args):
        """
        Calls anyconfig to load the configuration file, then loads any keys specified in the configuration file from Vault
        See https://python-anyconfig.readthedocs.io/en/latest/api/anyconfig.api.html#anyconfig.api.load for detailed invocation options.
        Args:
            path_spec: file(s) containing configuration info to parse
        Returns:
            configuration dictionary
        """
        config = load_base(path_spec, **args)
        return self.__process_vault_keys(config)

    def loads(self, content, **args):
        """
        Calls anyconfig to load the string into a dictionary, then loads any keys specified in the configuration from Vault
        See https://python-anyconfig.readthedocs.io/en/latest/api/anyconfig.api.html#anyconfig.api.loads for detailed invocation options.
        Args:
            content: string containing configuration info to parse
        Returns:
            configuration dictionary
        """
        config = loads_base(content, **args)
        return self.__process_vault_keys(config)

    def __process_vault_keys(self, config):
        """
        Takes the configuration loaded by AnyConfig and performs Vault secret loading and removes the vault_secrets section
        Args:
            - config: configuration dictionary from AnyConfig
        Returns:
            configuration dictionary
        """
        vault_config_parts = self.__vault_keys_retrieve(config)
        merge(config, vault_config_parts)
        config.pop('vault_secrets', None)
        return config

    def __vault_keys_retrieve(self, config):
        """
        Connects to the Vault to retrieve keys specified in the config dictionary
        Args:
            - config: configuration dict
        Returns:
            Updated vault configuration pieces
        """
        vault_config_parts = {}

        if self.pass_through_flag:
            warn("VaultAnyconfig is set to Passthrough mode, but secrets are configured in configuration. These secrets will not be loaded.", UserWarning)
            return vault_config_parts

        for secret, path in config.get("vault_secrets", {}).items():
            config_key_path = secret.split(".")
            read_vault_secret = self.read(path)['data'][config_key_path[-1]]
            config_part = self.__nested_config(config_key_path, read_vault_secret)
            merge(vault_config_parts, config_part)

        return vault_config_parts

    def __nested_config(self, path_list, value):
        """
        Recursively builds a dict path from a list of strings, and sets the value
        Args:
            - path_list: list of strings to build a path from
            - value: value to set at the path specified
        Returns:
            dictionary
        """
        config_part = {}

        if len(path_list) == 1:
            config_part[path_list[0]] = value
        else:
            config_part[path_list[0]] = self.__nested_config(path_list[1:], value)
        return config_part
