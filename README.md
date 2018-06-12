
ara-network
===========

Tools for launching nodes that interact with the _ARA Network_.

## Installation

```sh
$ npm install ara-network
```

## Usage

### ara-network-node(1)

#### Description

Launches nodes that interact with _ARA Network_

#### Usage

```sh
$ ann -h (help)
$ ann -t <name after 'ara-network-node'> (launch node by name)
$ ann -t . (launch node in current directory)
$ ann -t <relative path> (launch node by relative path)
```

#### Examples

*Launch ara-network-node-dht*
```bash
$ ann -t dht
```

### ara-network-secrets(1)

#### Description

Manage ARA keystores

#### Usage

```sh
$ ans -h (help)
$ ans -k <name> (create key)
$ ans --import -k <name> <path> (import key)
$ ans --export -k <name> [--public] [-o <output path>] (export key)
```

#### Examples

*Import the key stored in `./resolver.pub` as `localresolver`*
```bash
$ ans --import -k localresolver ./resolver.pub
```

*Export the public key of `localresolver` to `~/ssh/resolver.pub`*
```bash
$ ans --export -k localresolver --public -o ~/.ssh/resolver.pub
```

*Create a new key named `localresolver`*
```bash
$ ans -k localresolver
```

*Removes a key named `localresolver`*
```bash
ans -r localresolver
```
## Contributing

[How to contribute](/CONTRIBUTING.md)
[Commit message format](/COMMIT_FORMAT.md)

## See Also

[ara-network-node-dht](https://github.com/arablocks/ara-network-node-dht)

[ara-network-node-identity-archiver](https://github.com/arablocks/ara-network-node-identity-archiver)

[ara-network-node-identity-resolver](https://github.com/arablocks/ara-network-node-identity-resolver)

[ara-network-node-dns](https://github.com/arablocks/ara-network-node-dns)

[ara-network-node-signalhub](https://github.com/arablocks/ara-network-node-signalhub)

## License

LGPL-3.0
