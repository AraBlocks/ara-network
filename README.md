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

### `ara-network-keys(1)`
Create & Manage ARA Network Keys used in Handshake V2

#### Prerequisite
Create an ARA ID for the server node using the AID CLI or the `create()` method

#### Usage
```sh
$ ank -h (help)
$ ank -i <DID> \
      -s <shared-secret-string> \
      -n <keyring-name-entry> \
      -k <output-keyring-file> (create new shared network key)
```

#### Examples
* Create new shared network key for DID `86533105b0906a782b67f1aa8266a69c606fd6df948d22178390df4a395f267a` using `ara-archiver` as `secret` & `remote1` as the `keyring-name-entry`

```sh
$ ank -i 86533105b0906a782b67f1aa8266a69c606fd6df948d22178390df4a395f267a \
      -s ara-archiver \
      -n remote1 \
      -k ~/.ara/keyrings/ara-archiver
```

* The above command would create a set of shared network key files (i.e) a secret key and a public key
* If the mentioned keyRing file already exists for the mentioned DID, the `keyring-name-entry` would be just appended to the keyring array. Else, it will create a new set of files

#### Delegation
* Use the `secret-key`, `shared-secret-string` & `keyring-name-entry` to start up the remote node and then share the `public-key` along with the `shared-secret-string` & `keyring-name-entry` to all the peers who would want to communicate with the server

#### Appending
* When appending new entry into an existing keyring file, make sure to use a new `keyring-name-entry`. Also, make sure to use the same `DID` & `shared-secret-string` for appending

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
