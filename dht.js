const BitTorrentDHT = require('bittorrent-dht')
const crypto = require('ara-crypto')
const extend = require('extend')
const rc = require('./rc')()

const defaults = Object.assign({
  maxAge: Infinity,
  verify: crypto.verify,

  get nodeId() {
    return crypto.randomBytes(32)
  }
}, rc.network.dht)

/**
 * Create a BitTorrent DHT server.
 *
 * @public
 * @param {Object} [opts = {}]
 * @return {Object}
 */

function createServer(opts) {
  if (!opts || 'object' !== typeof opts) {
    // eslint-disable-next-line no-param-reassign
    opts = {}
  }
  // eslint-disable-next-line no-param-reassign
  opts = extend(true, {}, defaults, opts)
  const server = new BitTorrentDHT(opts)
  return server
}

/**
 * Create a BitTorrent DHT client.
 *
 * @public
 * @param {[Object]} opts
 * @return {Object}
 */

function createClient(opts) {
  if (!opts || 'object' !== typeof opts) {
    // eslint-disable-next-line no-param-reassign
    opts = {}
  }
  // eslint-disable-next-line no-param-reassign
  opts = extend(true, {}, defaults, opts)
  const client = new BitTorrentDHT(opts)
  return client
}

module.exports = {
  createClient,
  createServer,
  defaults,
}
