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

#### Examples

```sh
$ ann -h (help)
$ ann -t <name after 'ara-network-node'> (launch node by name)
$ ann -t . <if you are in the folder of a node> (launch node in file)
$ ann -t <relative path> (launch node by relative path)
```

### ara-network-secrets(1)

#### Description

Import, export or create keystores

#### Examples

```sh
$ ans -h (help)
$ ans -k <name> (create key)
$ ans --import -k <name> <path> (import key)
$ ans --export -k <name> [--public] [-o <output path>] (export key)
```

## See Also

[ara-network-node-dht](https://github.com/arablocks/ara-network-node-dht)
[ara-network-node-identity-archiver](https://github.com/arablocks/ara-network-node-identity-archiver)
[ara-network-node-identity-resolver](https://github.com/arablocks/ara-network-node-identity-resolver)
[ara-network-node-dns](https://github.com/arablocks/ara-network-node-dns)
[ara-network-node-signalhub](https://github.com/arablocks/ara-network-node-signalhub)

## License

LGPL-3.0
