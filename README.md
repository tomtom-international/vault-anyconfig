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

## Supported Secret Engines

Currently vault-anyconfig **only** supports version 1 and 2 of the key value store.

### kv2 Limitations

* vault-anyconfig **only** will read the latest version of a secret to maintain simplicity in the configuration file
* you must add `data` after the mountpoint for a kv2 secret, e.g. `secret/data/example-secret` due to limitations in the HVAC client

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

Additionaly, a `vault_files` section is included to retrieve files from Vault and write them to disk. This is discouraged (minimizing the time that
secrets are persisted should be prefered), but included for use with legacy applications which require a file path for secrets (e.g. TLS certificates).

#### Raw Config Example

```json
{
    "website": {
        "host": "http://acme.com",
        "site-name": "Great Products for Coyotes",
        "tls-key": "/etc/web/acme.com.key",
        "tls-cert": "/etc/web/acme.com.crt"
    },
    "vault_secrets": {
        "website.db_user": "secret/mysql/customer.user",
        "website.db_pwd": "secret/mysql/customer.password"
    },
    "vault_files": {
        "website.tls-key": "secret/website/proxy.key",
        "website.tls-cert": "secret/website/proxy.cert"
    }
}
```

##### Resulting Dictionary Example:

```json
{
    "website": {
        "host": "http://acme.com",
        "site-name": "great products",
        "tls-key": "/var/acme/acme.com.key",
        "tls-cert": "/var/acme/acme.com.crt",
        "db_user": "customer",
        "db_pwd": "customer-password"
    },
    "vault_files": {
        "website.tls-key": "secret/website/proxy.key",
        "website.tls-cert": "secret/website/proxy.cert"
    }
}
````

##### vault_secrets Usage

A `vault_secrets` entry must have a `config key` and a `secret path`. The `config_key` is a dot separated path to the configuration item that should
be added or updated. The `secret_path` is the path where the secret resides in Vault. As an example:

```json
{
    "website": {},
    "vault_secrets": {
       "website.db_user": "secret/mysql/customer"
    }    
}
```

In `vault_secrets`, `website.db_user` is the `config_key` and `secret/mysql/customer` is the `secret_path`. The key used on the `secret_path` in Vault
will be `db_user`.

By default, the final portional of the `config key` will be used as the key to the secret within Vault. However, it is possible to add a unique key
with a dot separator on the `secret_path`. By way of example:

```json
{
    "website": {},
    "vault_secrets": {
        "website.db_user": "secret/mysql/customer.user"
    }     
}
```
This example takes the value named `user` from the `mysql/customer` secret and maps it onto the the `db_user` key of the `website` portion.
This enables drawing from the same secret across different configurations without forcing all of the `config_key` names to be the same. For example,
if a cron job also required the `user` value from `mysql/customer.user` but its configuration named it `user`, you might end up with a configuration
file that looks like:

```json
{
    "website": {},
    "vault_secrets": {
        "mailer_cron.user": "secret/mysql/customer.user"
    }     
}
```

**Key-Value Store V2 Limitation**: You must include `data` after the mountpoint, for example, `secret/mysql/customer` should be
`secret/data/mysql/customer` when using V2.

##### vault_files Usage

**Note** Where ever possible, prefer to handle secrets as strings and use them only in memory. Only use this mode when configuring for applications
that require the secret to be provided as a file (a common requirement for a TLS keyfile).

**Note** Unlike `vault_secrets` the `vault_files` section is retained in the dictionary returned by vault_anyconfig, in order to retain the mapping
when writing the final configuration to file (e.g. in the CLI).

**Warning!** The `vault_files` functionality expects that it is being run as the user of the application, and must have appropriate permissions to
the files and location where files are to be stored.

**Warning!** `vault_files` will happily overwrite your files, and mantains no backups.

**Warning!** If the file location changes, it will not be deleted! Use responsibly.

There are two major ways to use the `vault_files` section. The first is to specify a file location directly, and the secret as the path.
For example:

```json
{
    "vault_files": {
        "/var/acme/acme.com.crt": "secret/website/proxy.key"
    }
}
```

The second method is to reference a key in the configuration. This avoids duplication of the file path in multiple parts of the configuration.

```json
{
    "website": {
        "tls-key": "/etc/web/acme.com.key",
        "tls-cert": "/etc/web/acme.com.crt",
    },
    "vault_files": {
        "website.tls-key": "secret/website/proxy.key",
        "website.tls-cert": "secret/website/proxy.cert"
    }
}
```

By default, `secret_path` uses `file` as the key within the Vault secret. However, the `secret_path` can use the same dot notation used in `vault_secrets` to specify the key, e.g. `secret/acme/secret-key.key`

**Warning!** The `secret_path` string can only use a dot (`.`) if separating the path from the key. Extra dots will cause vault_anyconfig to throw an
error.

**Key-Value Store V2 Limitation**: You must include `data` after the mountpoint, for example, `secret/website/proxy` should be
`secret/data/website/proxy` when using V2.


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
