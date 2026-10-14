# ShakenFist OVA client plugin

This plugin is used to add OVA import support to ShakenFist's client. This
functionality is optional in shakenfist-client, and is therefore presented
as a plugin.

## Installation

```bash
pip install shakenfist_client_ova
sf-client ova import appliance.ova
```

The plugin registers itself with `sf-client` through an entry point,
so once installed the `ova` commands appear automatically. Until the
first release reaches PyPI, install from a clone with `pip install .`
instead.

## Documentation

* [Importing an OVA](https://github.com/shakenfist/client-python-ova/blob/develop/docs/usage.md)
  -- what an import does, and why it stops on a descriptor it does not
  fully understand.
* [Development](https://github.com/shakenfist/client-python-ova/blob/develop/docs/development.md)
  -- setup, linting, CI and releasing.
