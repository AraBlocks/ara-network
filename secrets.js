'use strict'

const crypto = require('ara-crypto')

const DISCOVERY = 0
const REMOTE = 1
const CLIENT = 2
const NETWORK = 3

/**
 * Creates a network secrets document containing
 * a keystore and discovery key. The keystore stores
 * secret keys for the network and remote/client connections
 * wishing to communicate through a secret handshake.
 * @public
 * @param {?(Object)} opts
 * @param {?(String|Buffer)} opts.key
 * @param {?(String|Buffer)} opts.seed
 * @return {Object}
 */
function encrypt(opts) {
  if (null == opts || 'object' != typeof opts) {
    opts = {}
    opts.key = crypto.randomBytes(32)
  }

  const freelist = []
  const result = {}
  const keys = {}
  keys.remote = crypto.keyPair(seed('remote'))
  keys.client = crypto.keyPair(seed('client'))
  keys.network = crypto.keyPair(networkSeed())
  keys.discovery = crypto.discoveryKey(alloc(32, opts.key))

  const keystores = [ keys.discovery ]

  push(REMOTE, keys.remote)
  push(CLIENT, keys.client)
  push(NETWORK, keys.network)

  result.keystore = crypto.encrypt(alloc(Buffer.concat(keystores)), {
    key: alloc(16, opts.key),
    iv: alloc(crypto.randomBytes(16)),
  })

  result.discoveryKey = keys.discovery

  free()

  for (const k in keys) {
    if ('publicKey' in keys[k]) {
      keys[k].publicKey.fill(0)
    }

    if ('secretKey' in keys[k]) {
      keys[k].secretKey.fill(0)
    }
  }

  return result

  function alloc(size, mem) {
    let buffer = null
    if (Buffer.isBuffer(size)) { buffer = size }
    else { buffer = Buffer.allocUnsafe(size).fill(mem || 0) }
    if (false == freelist.includes(buffer)) { freelist.push(buffer) }
    return buffer
  }

  function free() {
    let buffer = null
    while (buffer = freelist.shift()) { buffer.fill(0) }
  }

  function push(index, keyPair) {
    keystores[index] = alloc(Buffer.concat([
      keyPair.publicKey, keyPair.secretKey
    ]))
  }

  function networkSeed() {
    return alloc(Buffer.concat([
      alloc(keys.remote.secretKey.slice(-16)),
      keys.client.secretKey.slice(0, 16)
    ]))
  }

  function seed(prefix) {
    if (opts.seed) {
      const buffer = alloc(32)
      buffer.fill(prefix + opts.seed)
      return buffer
    }
  }
}

/**
 * Decrypts an encrypt network secrets document into
 * a set of secret public and secret key pairs.
 * @public
 * @param {Object} doc
 * @param {Object} opts
 * @return {Object}
 */
function decrypt(doc, opts) {
  const keys = {}
  const buffer = crypto.decrypt(doc.keystore, opts)
  keys.discoveryKey = read(0, 32)
  keys.remote = {
    publicKey: read(32, 32),
    secretKey: read(64, 64),
  }

  keys.client = {
    publicKey: read(128, 32),
    secretKey: read(160, 64),
  }

  keys.network = {
    publicKey: read(224, 32),
    secretKey: read(256, 64),
  }

  return keys

  function read(offset, length) {
    return buffer.slice(offset, offset + length)
  }
}

module.exports = {
  encrypt,
  decrypt,
}
