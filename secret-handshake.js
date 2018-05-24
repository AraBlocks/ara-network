'use strict'

const handshake = require('secret-handshake')
const isBuffer = require('is-buffer')
const pull = require('pull-stream')

/**
 * Pull (pipe) a source stream into a destination
 * stream piped back into the source stream.
 * @public
 * @param {Stream} source
 * @param {Stream} destination
 * @return {Stream}
 */
function connect(source, destination) {
  return pull(source, destination, source)
}

/**
 * Creates a secret handshake server for a
 * client with key pair and a given network key.
 * @public
 * @param {Object} opts
 * @param {Function} opts.onauthorize
 * @param {Object} opts.client
 * @param {Object} opts.client.publicKey
 * @param {Object} opts.client.secretKey
 * @param {Object} opts.network
 * @param {Object} opts.network.key
 * @return {Object}
 * @throws TypeError
 */
function createServer(opts) {
  if (null == opts || 'object' != typeof opts) {
    throw new TypeError(
      "ara-network.secret-handshake.createServer: Expecting object.")
  }

  if (null == opts.client || 'object' != typeof opts.client) {
    throw new TypeError(
      "ara-network.secret-handshake.createServer: Expecting client to be an object.")
  }

  if (null == opts.network || 'object' != typeof opts.network) {
    throw new TypeError(
      "ara-network.secret-handshake.createServer: Expecting network to be an object.")
  }

  if (false == isBuffer(opts.network.key)) {
    throw new TypeError(
      "ara-network.secret-handshake.createServer: Expecting network key to be a buffer.")
  }

  const { client, onauthorize, network } = opts
  const server = shs.createServer(client, onauthorize, network.key)
  return server
}

/**
 * Creates a secret handshake client for a
 * remote with keys and a given network key.
 * @public
 * @param {Object} opts
 * @param {Function} opts.onauthorize
 * @param {Object} opts.client
 * @param {Object} opts.client.publicKey
 * @param {Object} opts.client.secretKey
 * @param {Object} opts.network
 * @param {Object} opts.network.key
 * @return {Object}
 * @throws TypeError
 */
function createClient(opts) {
  if (null == opts || 'object' != typeof opts) {
    throw new TypeError(
      "ara-network.secret-handshake.createClient: Expecting object.")
  }

  if (null == opts.client || 'object' != typeof opts.client) {
    throw new TypeError(
      "ara-network.secret-handshake.createClient: Expecting client to be an object.")
  }

  if (null == opts.network || 'object' != typeof opts.network) {
    throw new TypeError(
      "ara-network.secret-handshake.createClient: Expecting network to be an object.")
  }

  if (false == isBuffer(opts.network.key)) {
    throw new TypeError(
      "ara-network.secret-handshake.createClient: Expecting network key to be a buffer.")
  }

  const { server, network } = opts
  const client = shs.createClient(server, network.key)
  return client
}

module.exports = {
  createServer,
  createClient,
  connect,
}
