# VaultAnyconfig

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

#### Example:

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

#### Example:

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
and the values are the path to the secret in Vault. Note as well, the key for the secret in Vault must match the name of the key you are inserting
into your configuration.

#### Raw Config Example:
```json
{
    "acme": {
        "host": "http://acme.com",
        "site-name": "great products"
    },
    "vault_secrets": {
        "acme.user": "secret/acme/user",
        "acme.pwd": "secret/acme/user"
    }
}
```

##### Resulting Dictionary Example:

```json
{
    "acme": {
        "host": "http://acme.com",
        "site-name": "great products",
        "user": "sample-user",
        "pwd": "sample-password"
    }
}
```

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
