'use strict'

const BitTorrentDHT = require('bittorrent-dht')
const crypto = require('ara-crypto')
const extend = require('extend')
const debug = require('debug')('ara:network:dht')

const defaults = {
  maxAge: Infinity,
  verify: crypto.verify,

  get nodeId() {
    return crypto.randomBytes(32)
  }
}

/**
  * Create a BitTorrent DHT server.
  * @public
  * @param {?(Object)} opts
  * @return {Object}
  */
function createServer(opts) {
  if (!opts || 'object' != typeof opts) { opts = {} }
  opts = extend(true, {}, defaults, opts)
  const server = new BitTorrentDHT(opts)
  return server
}

/**
 * Create a BitTorrent DHT client.
  * @public
  * @param {?(Object)} opts
  * @return {Object}
 */
function createClient(opts) {
  if (!opts || 'object' != typeof opts) { opts = {} }
  opts = extend(true, {}, defaults, opts)
  const client = new BitTorrentDHT(opts)
  return client
}

module.exports = {
  createClient,
  createServer,
}
