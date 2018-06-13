<img src="https://github.com/AraBlocks/docs/blob/master/ara.png" width="30" height="30" /> ara-network
===========

[![Build Status](https://travis-ci.com/AraBlocks/ara-network.svg?token=r6p7pesHZ9MRJsVsrYFe&branch=master)](https://travis-ci.com/AraBlocks/ara-network)

Tools for launching nodes that interact with the _ARA Network_.

## Status
This project is still in alpha development.

## Dependencies
- [Node](https://nodejs.org/en/download/) 

## Installation

```bash
$ npm install ara-network
```

## API

### `ara-network-node(1)`

Launches nodes that interact with _ARA Network_.

#### Usage

```bash
$ ann -h (help)
$ ann -t <name after 'ara-network-node'> (launch node by name)
$ ann -t . (launch node in current directory)
$ ann -t <relative path> (launch node by relative path)
```

#### Example

*Launch ara-network-node-dht*
```bash
$ ann -t dht
```

### `ara-network-secrets(1)`

Manage ARA keystores.

#### Usage

```bash
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
- [Commit message format](/.github/COMMIT_FORMAT.md)
- [Commit message examples](/.github/COMMIT_FORMAT_EXAMPLES.md)
- [How to contribute](/.github/CONTRIBUTING.md)

## See Also
- [ara-network-node-dht](https://github.com/arablocks/ara-network-node-dht)
- [ara-network-node-dns](https://github.com/arablocks/ara-network-node-dns)
- [ara-network-node-signalhub](https://github.com/arablocks/ara-network-node-signalhub)
- [ara-network-node-identity-archiver](https://github.com/arablocks/ara-network-node-identity-archiver)
- [ara-network-node-identity-resolver](https://github.com/arablocks/ara-network-node-identity-resolver)

## License
LGPL-3.0
