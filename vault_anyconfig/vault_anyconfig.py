"""
Provides an extension to the HVAC Hashicorp Vault client for reading and writing configuration files.
"""
from warnings import warn
from os import chmod
from os.path import abspath, isfile
from stat import S_IRUSR, S_IWUSR

from hvac import Client
from anyconfig import (
    dump as dump_base,
    dumps as dumps_base,
    load as load_base,
    loads as loads_base,
    merge,
)


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
            vault_config = load_base(vault_config_file).get("vault_config", {})

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

        Special cases:
            - kubernetes: Kubernetes authentication can optionally provide a token_path field in the credentials file rather than directly providing
                the JWT. Typically this path should be `/var/run/secrets/kubernetes.io/serviceaccount` See
                https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#service-account-admission-controller

        Args:
            - vault_creds_file: file containing the credentials for the Vault
        Returns:
            bool of authenication status
        """
        if self.pass_through_flag or self.is_authenticated():
            return True

        creds = load_base(vault_creds_file)["vault_creds"]
        auth_method = "auth_" + creds["auth_method"]
        creds.pop("auth_method", None)

        # Special cases
        if auth_method == "auth_kubernetes":
            token_path = creds.pop("token_path", None)
            if token_path:
                with open(token_path, "r") as token_file:
                    creds['jwt'] = token_file.read()

        try:
            method = getattr(self, auth_method)
        except AttributeError:
            raise NotImplementedError(
                "HVAC does not provide {} as an authentication method".format(
                    auth_method
                )
            )

        method(**creds)
        return self.is_authenticated()

    def dump(self, data, out, process_secret_files=False, **args):
        """
        First updates the provided dictionary with keys from the Vault, then calls anyconfig to dump out a configuration file.
        See https://python-anyconfig.readthedocs.io/en/latest/api/anyconfig.api.html#anyconfig.api.dump for detailed invocation options.

        Args:
            data: configuration dict
            out: file[path] (or file-like) object to write to
        """
        updated_data = self.__process_vault_keys(data)

        if process_secret_files:
            self.__process_vault_files(updated_data)

        dump_base(updated_data, out, **args)

    def dumps(self, data, process_secret_files=False, **args):
        """
        First updates the provided dictionary with keys from the Vault, then calls anyconfig to dump out string
        See https://python-anyconfig.readthedocs.io/en/latest/api/anyconfig.api.html#anyconfig.api.dump for detailed invocation options.

        Args:
            data: configuration dict
        Returns:
            String with the configuration
        """
        updated_data = self.__process_vault_keys(data)

        if process_secret_files:
            self.__process_vault_files(updated_data)

        return dumps_base(updated_data, **args)

    def load(self, path_spec, process_secret_files=False, **args):
        """
        Calls anyconfig to load the configuration file, then loads any keys specified in the configuration file from Vault
        See https://python-anyconfig.readthedocs.io/en/latest/api/anyconfig.api.html#anyconfig.api.load for detailed invocation options.

        Args:
            path_spec: file(s) containing configuration info to parse
        Returns:
            configuration dictionary
        """
        config = load_base(path_spec, **args)

        if process_secret_files:
            self.__process_vault_files(config)

        return self.__process_vault_keys(config)

    def loads(self, content, process_secret_files=False, **args):
        """
        Calls anyconfig to load the string into a dictionary, then loads any keys specified in the configuration from Vault
        See https://python-anyconfig.readthedocs.io/en/latest/api/anyconfig.api.html#anyconfig.api.loads for detailed invocation options.

        Args:
            content: string containing configuration info to parse
        Returns:
            configuration dictionary
        """
        config = loads_base(content, **args)

        if process_secret_files:
            self.__process_vault_files(config)

        return self.__process_vault_keys(config)

    def save_file_from_vault(self, file_path, secret_path, secret_key):
        """
        Retrieves a file (stored as a string) from a Hashicorp Vault secret and renders it to the specified file.
        Attempts to set the permission of the file to read-only.
        Args:
            - file_path: file path to write secret file to
            - secret_path: secret's path in Vault
            - secret_key: key in the secret in Vault to access
        """
        secret_file_string = self.__process_response(
            self.read(secret_path), secret_key)

        real_file_path = abspath(file_path)
        if isfile(file_path):
            try:
                chmod(real_file_path, S_IWUSR)
            except PermissionError:
                warn(
                    "Unable to set the file permission to write for {} before updating its contents.".format(
                        real_file_path
                    ),
                    UserWarning,
                )

        with open(real_file_path, "w") as secret_file:
            secret_file.write(secret_file_string)

        # Set file to read-only for user
        try:
            chmod(real_file_path, S_IRUSR)
        except PermissionError:
            warn(
                "Unable to set the file permission to read-only for {} after updating its contents.".format(
                    real_file_path
                ),
                UserWarning,
            )

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
        config.pop("vault_secrets", None)
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
            warn(
                "VaultAnyconfig is set to Passthrough mode, but secrets are configured in configuration. These secrets will not be loaded.",
                UserWarning,
            )
            return vault_config_parts

        for secret, path in config.get("vault_secrets", {}).items():
            config_key_path = secret.split(".")
            secret_path = path

            # Optionally map the key in the configuration to a different key in the Vault
            secret_path_split = secret_path.split(".")
            if len(secret_path_split) > 1:
                secret_path = "".join(secret_path_split[:-1])
                secret_key = secret_path_split[-1]
            else:
                secret_key = config_key_path[-1]

            read_vault_secret = self.__process_response(
                self.read(secret_path), secret_key)

            config_part = self.__get_nested_config(
                config_key_path, read_vault_secret)
            merge(vault_config_parts, config_part)

        return vault_config_parts

    def __process_vault_files(self, config):
        """
        Gets the files specified in vault_files and writes them to disc in the specified location.
        Over-writes the file if it exists, and leave it with read-only for the executing user (if it has permission to do so).
        Args:
            - config: configuration dict
        """
        if self.pass_through_flag:
            warn(
                "VaultAnyconfig is set to Passthrough mode, but secret_files are configured in configuration. These files will not be loaded.",
                UserWarning,
            )
            return

        for file_path, secret in config.get("vault_files", {}).items():
            # Check if the filepath actually is a key in the configuration file, and use it if it is
            real_file_path = self.__get_value_nested_config(
                file_path.split("."), config
            )
            if not real_file_path:
                real_file_path = file_path

            secret_split = secret.split(".")
            if len(secret_split) > 1 and secret[-1] != "." and secret[0] != ".":
                secret_path = ".".join(secret_split[0:-1])
                secret_key = secret_split[-1]
            else:
                secret_path = secret
                secret_key = "file"
            self.save_file_from_vault(real_file_path, secret_path, secret_key)

        return

    @classmethod
    def __process_response(cls, read_response, secret_key):
        """
        Detects the secret engine returning a secret (currently *only* supports key-value versions 1 and 2) and returns the requested key from the
        secret.
        Args:
            - read_response: response from HVAC read function
            - secret_key: secret key being retrieved
        Returns:
            secret string
        """
        if cls.__is_key_value_v1(read_response, secret_key):
            secret_string = read_response['data'][secret_key]
        elif cls.__is_key_value_v2(read_response):
            secret_string = read_response['data']['data'][secret_key]
        else:
            raise RuntimeError(
                "Invalid response recieved. Possibly due to an unsupported secrets engine, vault-anyconfig currently only supports kv1 and kv2.")
        return secret_string

    @staticmethod
    def __is_key_value_v1(read_response, secret_key):
        """
        Checks if the response is from the key value v1 secret engine.
        See https://www.vaultproject.io/api/secret/kv/kv-v1.html#sample-response-1
        Args:
            - read_response: response from HVAC read function
            - secret_key: secret key being retrieved
        Returns:
            Bool
        """
        return isinstance(read_response.get('data', {}).get(secret_key, {}), str)

    @staticmethod
    def __is_key_value_v2(read_response):
        """
        Checks if the response is from the key value v2 secret engine
        See https://www.vaultproject.io/api/secret/kv/kv-v2.html#sample-response-1
        Args:
            - read_response: response from HVAC read function
        Returns:
            Bool
        """
        return isinstance(read_response.get('data', {}).get('data', ''), dict)

    def __get_nested_config(self, path_list, value):
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
            config_part[path_list[0]] = self.__get_nested_config(
                path_list[1:], value)
        return config_part

    def __get_value_nested_config(self, path_list, config):
        """
        Recursively builds a dict path from a list of strings, and determines if it exists

        Args:
            - path_list: list of strings to build a path from
        Returns:
            value at path
        """
        local_config = config.get(path_list[0], None)

        if len(path_list) <= 1 or not local_config:
            return config.get(path_list[0], None)
        return self.__get_value_nested_config(path_list[1:], local_config)
