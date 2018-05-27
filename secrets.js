'use strict'

const crypto = require('ara-crypto')

const DISCOVERY = 0
const NETWORK = 1
const CLIENT = 3
const REMOTE = 2

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
  const freelist = []
  const keys = {}

  const result = {
    public: {},
    secret: {},
  }

  if (null == opts || 'object' != typeof opts) {
    opts = {}
    opts.key = alloc(crypto.randomBytes(32))
  }

  keys.remote = crypto.keyPair(seed('remote'))
  keys.client = crypto.keyPair(seed('client'))
  keys.network = crypto.keyPair(networkSeed())
  keys.discoveryKey = crypto.discoveryKey(alloc(32, opts.key))

  const keystores = {
    public: [ // 160 = 32 + 32 + 32 + 64
      keys.discoveryKey, // 32
      keys.network.publicKey, // 32
      keys.remote.publicKey, // 32
      keys.client.secretKey, // 64
    ],

    secret: [ // 224 = 32 + 64 + 64 + 64
      keys.discoveryKey, // 32
      keys.network.secretKey, // 64
      keys.remote.secretKey, // 64
      keys.client.secretKey, // 64
    ],
  }

  const iv = alloc(crypto.randomBytes(16))
  const key = alloc(16, opts.key)
  const digest = alloc(crypto.blake2b(Buffer.concat(freelist)))

  const buffers = {
    public: alloc(Buffer.concat(keystores.public)),
    secret: alloc(Buffer.concat(keystores.secret)),
  }

  result.public.discoveryKey = keys.discoveryKey.toString('hex')
  result.public.keystore = crypto.encrypt(buffers.public, {key, iv})
  result.public.digest = digest.toString('hex')

  result.secret.discoveryKey = keys.discoveryKey.toString('hex')
  result.secret.keystore = crypto.encrypt(buffers.secret, {key, iv})
  result.secret.digest = digest.toString('hex')

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
 *
 * - Discovery keys are 32 bytes and appear at the header of a decrypted buffer
 * - Public keys are 32 bytes and only appear in a public keystore
 * - Secret keys are 64 bytes and can appear in both public and private keystores
 *
 * The order in which keys appear in a buffer are detailed below:
 * 1 - 32 byte discovery key
 * 2 - 32 byte network public key or 64 byte network private key
 * 3 - 32 byte remote public key or 64 byte remote private key
 * 4 - 64 byte client private key
 *
 * @public
 * @param {Object} doc
 * @param {Object} opts
 * @return {Object}
 */
function decrypt(doc, opts) {
  const keys = {}
  const buffer = crypto.decrypt(doc.keystore, opts)
  keys.discoveryKey = read(DISCOVERY, 32)

  if (opts.public) {
    keys.network = { publicKey: read(NETWORK * 32, 32) }
    keys.remote = { publicKey: read(REMOTE * 32, 32) }
    keys.client = { secretKey: read(CLIENT * 32, 64) }
  } else {
    keys.network = { publicKey: read(NETWORK * 64, 64) }
    keys.remote = { publicKey: read(REMOTE * 64, 64) }
    keys.client = { secretKey: read(CLIENT * 64, 64) }
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
