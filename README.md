# VaultAnyconfig

[![Azure DevOps builds](https://img.shields.io/azure-devops/build/tomtomweb/GitHub-TomTom-International/13/master.svg)](https://dev.azure.com/tomtomweb/GitHub-TomTom-International/_build/latest?definitionId=13&branchName=master)
[![Azure DevOps tests](https://img.shields.io/azure-devops/tests/tomtomweb/GitHub-TomTom-International/13/master.svg)](https://dev.azure.com/tomtomweb/GitHub-TomTom-International/_build/latest?definitionId=13&branchName=master)
[![Azure DevOps coverage](https://img.shields.io/azure-devops/coverage/tomtomweb/GitHub-TomTom-International/13/master.svg)](https://dev.azure.com/tomtomweb/GitHub-TomTom-International/_build/latest?definitionId=13&branchName=master)

[![PyPI - Version](https://img.shields.io/pypi/v/vault-anyconfig.svg)](https://pypi.org/project/vault-anyconfig/)
[![PyPI - License](https://img.shields.io/pypi/l/vault-anyconfig.svg)](https://pypi.org/project/vault-anyconfig/)
[![PyPI - Python Versions](https://img.shields.io/pypi/pyversions/vault-anyconfig.svg)](https://pypi.org/project/vault-anyconfig/)
[![PyPI - Format](https://img.shields.io/pypi/format/vault-anyconfig.svg)](https://pypi.org/project/vault-anyconfig/)
[![PyPI - Status](https://img.shields.io/pypi/status/vault-anyconfig.svg)](https://pypi.org/project/vault-anyconfig/)
[![PyUp - Updates](https://pyup.io/repos/github/tomtom-international/vault-anyconfig/shield.svg)](https://pyup.io/repos/github/tomtom-international/vault-anyconfig/)

Extends the [HVAC Hashicorp Vault Client](https://github.com/hvac/hvac) with the load and dump functionality from
[anyconfig](https://github.com/ssato/python-anyconfig). This allows automatic mixing in of secrets from Vault, allowing you to store a configuration
file with all details populated save for secrets, and then access Hashicorp Vault to load the secrets into the in-memory dictionary.

## Files and Formatting

There are three configuration files, which can be stored in one, two or three files total as long as they are correctly written.

Examples in this section will be in JSON, but any file format supported by anyconfig can be used.

### Vault Configuration File

This configures the connection to the Vault, and must contain at least one member (usually the url parameter). If this section is not provided or is
left empty, then the Vault instance will **not** be configured, and instead only the anyconfig functionality will be used.

The section must be named `vault_config`, and can contain any of the parameters valid for initializing an [HVAC client](https://github.com/hvac/hvac/blob/master/hvac/v1/__init__.py).

#### Example

```json
{
    "vault_config": {
        "url": "https://vault.acme.com:8200"
    }
}
```

### Vault Authentication File

This provides authentication for use with the `auth_from_file` method, and must be named `vault_creds`. It should contain a member named `auth_method`
which should correspond with one of the auth method from [the HVAC Client](https://hvac.readthedocs.io/en/latest/usage/auth_methods/index.html) (without the "`auth_`" prefix), e.g. `approle`. The remaining members
should match the parameters for the specified auth method.

#### Example

```json
{
    "vault_creds": {
        "role_id": "sample-role-id",
        "secret_id": "sample-secret-id",
        "auth_method": "approle"
    }
}
```

### Main Configuration File

The main configuration file should consist of the configuration sections you need **without** the secrets included (unless passthrough mode is desired)
and a section named `vault_secrets`. In the `vault_secrets` section, the keys are dot separated paths for the keys to insert into your configuration,
and the values are the path to the secret in Vault. Please see the `vault_secrets` usage section for the different ways to specify secrets.

There is an additional section, `vault_files` that allows you to specify a filepath (or reference a file path in a configuration section) and map it
to a Vault secret. If this mode is used, then it will over-write any file which already exists at the specified path, and then set read-only
permissions on the file. If the appropriate permissions are missing, then an error will be thrown. This section should only been used when passing
the secret string in memory is not possible, for example if the application is only able to read a certificate from a file. Unlike the `vault_secrets`
section this section will be included in the returned dictionary, so if this feature is used the calling application must handle this section.

#### Raw Config Example

```json
{
    "acme": {
        "host": "http://acme.com",
        "site-name": "great products",
        "secret-key": "/var/acme/acme.key"
    },
    "vault_secrets": {
        "acme.user": "secret/acme/user",
        "acme.pwd": "secret/acme/user"
    },
    "vault_files": {
        "acme.secret-key": "secret/acme/secret-key",
        "/var/acme/very-secret.key": "secret/acme/very-secret"
    }
}
```

##### Resulting Dictionary Example:

```json
{
    "acme": {
        "host": "http://acme.com",
        "site-name": "great products",
        "secret-key": "/var/acme/acme.key",
        "user": "sample-user",
        "pwd": "sample-password"
    },
    "vault_files": {
        "acme.secret-key": "secret/acme/secret-key",
        "/var/acme/very-secret.key": "secret/acme/very-secret"
    }
}
````

##### vault_secrets Usage

A `vault_secrets` entry must have a `config key` and a `secret path`. The `config_key` is a dot separated path to the configuration item that should
be added or updated. The `secret_path` is the path where the secret resides in Vault. As an example:

```json
{
    "acme": {},
    "vault_secrets": {
        "acme.pwd": "secret/acme/secret-password"
    }    
}
```

In `vault_secrets`, `acme.pwd` is the `config_key` and `secret/acme/secret-password` is the `secret_path`. The key used on the `secret_path` in Vault
will be `pwd`.

By default, the final portional of the `config key` will be used as the key to the secret within Vault. However, it is possible to add a unique key
with a dot separator on the `secret_path`. By way of example:

```json
{
    "acme": {},
    "vault_secrets": {
        "acme.pwd": "secret/acme/secret-password.password"
    }     
}
```
This example is effectively the same as the first, but when accessing the `secret_path` in Vault, the key `password` will be used rather than `pwd`.

##### vault_files Usage

There are two major ways to use the `vault_files` section. The first is to specify a file location directly as the key, and the secret as the path.
For example:
```json
{
    "vault_files": {
        "/var/acme/secret.key": "secret/acme/secret-key"
    }
}
```

The second method is to reference a key in the configuration. This way if the secret file's location is configurable, changes to its location will be
automatically handled when writing out the file. **Warning!** If the file location changes, it will not be deleted! For example:
```json
{
    "acme": {
        "secret-key": "/opt/server/acme.key"
    },
    "vault_files": {
        "acme.secret-key": "secret/acme/secret-key"
    }
}
```

By default, `secret_path` uses `file` as the key within the Vault secret. However, the `secret_path` can use the same dot notation used in `vault_secrets` to specify the key, e.g. `secret/acme/secret-key.key`

### Guidance for Configuration Files

Although all three files can be combined into a single file, it is recommend that you separate out the `vault_creds` and `vault_config` sections into
their own file(s) and use restrictive permissions on them, e.g. `400`, since the secrets required to access Vault must be present in these files.

## Usage

### Initialization

VaultAnyconfig can be initalized in three ways (for two different modes):

1. From a vault configuration file (see files and formatting)
2. By specifying the parameters used in initializing an [HVAC client](https://github.com/hvac/hvac/blob/master/hvac/v1/__init__.py).
3. By providing no parameters (or a configuration file with an empty `vault_config` section) in which case it is in passthrough mode, where secrets are **not** loaded from Vault.

### Authentication With Vault

You can use `auth_from_file` by providing a file as explained in the files and formatting section, or you can directly use the auth methods from
[the HVAC Client](https://hvac.readthedocs.io/en/latest/usage/auth_methods/index.html). If passthrough mode is set, `auth_from_file` will always return
true, but the HVAC client methods will fail, so it is recommended to use `auth_from_file` where possible.

#### Loading/Saving Files with Keys Inserted

Simply call the `load`, `loads`, `dump` or `dumps` methods as need. Invocation is the same as for directly calling the [anyconfig methods](https://python-anyconfig.readthedocs.io/en/latest/api/anyconfig.api.html#anyconfig.api.load).
