'use strict'

const { resolve } = require('path')
const secrets = require('./secrets')
const crypto = require('ara-crypto')
const debug = require('debug')('ara:network:secrets')
const pify = require('pify')
const rc = require('./rc')()
const fs = require('fs')

const DISCOVERY = 0
const NETWORK = 1
const REMOTE = 2
const CLIENT = 3

const PKX = Buffer.from('PKX')  // public keystore header
const SKX = Buffer.from('SKX')  // secret keystore header

const toHex = (b) => b && b.toString('hex')

function ensureKeyPair(keyPair) {
  if ('publicKey' in keyPair && 'secretKey' in keyPair) {
    return keyPair
  } else if (Buffer.isBuffer(keyPair) && 64 == keyPair.length) {
    const publicKey = keyPair.slice(32)
    const secretKey = keyPair
    return { publicKey, secretKey }
  } else if (Buffer.isBuffer(keyPair) && 32 == keyPair.length) {
    const publicKey = keyPair
    const secretKey = null
    return { publicKey, secretKey }
  } else {
    return null
  }
}

/**
 * Creates a network secrets document containing
 * a keystore and discovery key. The keystore stores
 * secret keys for the network and remote/client connections
 * wishing to communicate through a secret handshake.
 *
 * @public
 *
 * @param {Object} opts
 * @param {(String|Buffer)} opts.key
 * @param {(String|Buffer)} [opts.seed]
 *
 * @return {Object}
 */

function encrypt(opts) {
  const keys = {}

  if (null == opts || 'object' != typeof opts) {
    throw new TypeError("encrypt: Expecting object.")
  }

  if (false == Buffer.isBuffer(opts.key) && 'string' != typeof opts.key) {
    throw new TypeError("encrypt: Expecting buffer or string as key.")
  }

  // use given remote + client keys, or generate
  keys.remote = ensureKeyPair(opts.remote || crypto.keyPair(seed('remote')))
  keys.client = ensureKeyPair(opts.client || crypto.keyPair(seed('client')))

  if (null == keys.remote || null == keys.remote.secretKey) {
    throw new TypeError("encrypt: Expecting remote secret key.")
  }

  if (null == keys.client || null == keys.client.secretKey) {
    throw new TypeError("encrypt: Expecting client secret key.")
  }

  // network seed depends on remote + client key pairs
  keys.network = crypto.keyPair(networkSeed(keys.remote, keys.client))

  // discovery keys are unique per generation
  keys.discoveryKey = crypto.discoveryKey(crypto.randomBytes(32))

  // encrypt and pack keys into document
  return pack(keys, opts)

  function networkSeed(remote, client) {
    return Buffer.concat([
      remote.secretKey.slice(-16),
      client.secretKey.slice(0, 16),
    ])
  }

  function seed(prefix) {
    const buffer = Buffer.allocUnsafe(32)
    prefix = Buffer.from(prefix)
    if (opts.seed) {
      buffer.fill(Buffer.concat([prefix, opts.seed]))
    } else {
      buffer.fill(Buffer.concat([prefix, crypto.randomBytes(32 - prefix.length)]))
    }
    return buffer
  }
}

/**
 * Create encrypted document of keys
 *
 * @param  {Object} keys
 * @param  {Object} keys.discoveryKey
 * @param  {Object} keys.network.publicKey
 * @param  {Object} keys.network.secretKey
 * @param  {Object} keys.remote.publicKey
 * @param  {Object} keys.remote.secretKey
 * @param  {Object} keys.client.secretKey
 * @param  {Object} opts
 * @param  {Object} opts.key Encryption key
 *
 * @return {[type]}      [description]
 */

function pack(keys, opts) {
  const freelist = []
  const result = { public: {}, secret: {} }
  const keystores = {
    public: [ // 163 = 3 + 32 + 32 + 32 + 64
      PKX,
      keys.discoveryKey, // 32
      keys.network.publicKey, // 32
      keys.remote.publicKey, // 32
      keys.client.secretKey, // 64
    ],

    secret: [ // 227 = 3 + 32 + 64 + 64 + 64
      SKX,
      keys.discoveryKey, // 32
      keys.network.secretKey, // 64
      keys.remote.secretKey, // 64
      keys.client.secretKey, // 64
    ],
  }

  if (false == Buffer.isBuffer(opts.key)) {
    opts.key = Buffer(opts.key)
  }

  const key = alloc(crypto.blake2b(opts.key, 16))
  const buffers = {
    public: alloc(Buffer.concat(keystores.public)),
    secret: alloc(Buffer.concat(keystores.secret)),
  }

  const iv = alloc(crypto.randomBytes(16))
  const digest = alloc(crypto.blake2b(Buffer.concat(freelist)))

  result.public.discoveryKey = keys.discoveryKey.toString('hex')
  result.public.digest = digest.toString('hex')
  result.public.keystore = crypto.encrypt(buffers.public, {key, iv})

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

  /**
   * Create buffer of specific size
   *
   * @private
   *
   * @param  {Number} size Size of buffer
   * @param  {Buffer} mem  Initial content
   *
   * @return {Buffer}
   */

  function alloc(size, mem) {
    let buffer = null

    if (Buffer.isBuffer(size)) buffer = size
    else buffer = Buffer.allocUnsafe(size).fill(mem || 0)

    if (false == freelist.includes(buffer)) freelist.push(buffer)

    return buffer
  }

  /**
   * Overwrite buffer with 0s
   *
   * @private
   */

  function free() {
    let buffer = null

    while (buffer = freelist.shift()) buffer.fill(0)
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
 * 0 - 3 byte header containing the `PKX` or `SKX` string denoting keystore type
 * 1 - 32 byte discovery key
 * 2 - 32 byte network public key or 64 byte network private key
 * 3 - 32 byte remote public key or 64 byte remote private key
 * 4 - 64 byte client private key
 *
 * @public
 *
 * @param {Object} doc
 * @param {Object} opts
 *
 * @return {Object}
 */

function decrypt(doc, opts) {
  if (false == Buffer.isBuffer(opts.key)) {
    opts.key = Buffer(opts.key)
  }

  const key = crypto.blake2b(opts.key, 16)
  const buffer = crypto.decrypt(doc.keystore, Object.assign({}, opts, {key}))
  const offset = 3 // for header
  const header = read(0, offset)
  const keys = {
    discoveryKey: null,
    network: { publicKey: null, secretKey: null },
    remote: { publicKey: null, secretKey: null },
    client: { publicKey: null, secretKey: null },
  }

  keys.discoveryKey = read(offset + DISCOVERY, 32)

  if (0 == Buffer.compare(PKX, header)) {
    const shift = offset
    const size = 32

    // parse keys
    keys.network.publicKey = read((NETWORK * 32) + shift, 32)
    keys.remote.publicKey = read((REMOTE * 32) + shift, 32)
    keys.client.secretKey = read((CLIENT * 32) + shift, 64)

    // derive public key
    keys.client.publicKey = keys.client.secretKey.slice(32)
  } else if (0 == Buffer.compare(SKX, header)) {
    const shift = offset - keys.discoveryKey.length
    const size = 64

    // parse keys
    keys.network.secretKey = read((NETWORK * size) + shift, size)
    keys.remote.secretKey = read((REMOTE * size) + shift, size)
    keys.client.secretKey = read((CLIENT * size) + shift, size)

    // derivce public keys
    keys.network.publicKey = keys.network.secretKey.slice(32)
    keys.remote.publicKey = keys.remote.secretKey.slice(32)
    keys.client.publicKey = keys.client.secretKey.slice(32)
  } else {
    throw new TypeError("Malformed secrets keystore buffer.")
  }

  return keys

  function read(offset, length) {
    return buffer.slice(offset, offset + length)
  }
}

/**
 * Load secrets by name from the secrets root directory.
 * Secrets are indexed by the blake2b hash of their value.
 *
 * @public
 *
 * @param {Object} opts
 *
 * @return {Object}
 */

async function load(opts) {
  if (null == opts || 'object' != typeof opts) {
    throw new TypeError("load: Expecting object.")
  }

  if (false == Buffer.isBuffer(opts.key) && 'string' != typeof opts.key) {
    throw new TypeError("load: Expecting key to be a buffer or string.")
  }

  const key = crypto.blake2b(Buffer.from(opts.key), 16).toString('hex')
  const paths = { public: null, secret: null }
  const result = { public: null, secret: null }
  paths.secret = resolve(opts.root || rc.network.secrets.root, key)
  paths.public = paths.secret + '.pub'

  if (false !== opts.public) {
    try {
      await pify(fs.access)(paths.public)
      result.public = await pify(fs.readFile)(paths.public, 'utf8')
      result.public = JSON.parse(result.public)
    } catch (err) { debug(err) }
  }

  if (true !== opts.public) {
    try {
      await pify(fs.access)(paths.secret)
      result.secret = await pify(fs.readFile)(paths.secret, 'utf8')
      result.secret = JSON.parse(result.secret)
    } catch (err) {
      debug(err)
    }
  }

  return result
}

/**
 * Derive a resolution document from a secret containing
 * public and secret keys if available.
 *
 * @public
 *
 * @param {Object} secret
 * @param {Object} opts
 *
 * @return {Object}
 */

function derive(secret, opts) {
  const doc = decrypt(secret, opts)
  const result = { public: null, secret: null, }
  if (doc.remote.secretKey) {
    return { secret }
  } else {
    return { public: secret }
  }
}

module.exports = {
  encrypt,
  decrypt,
  derive,
  load,
}
