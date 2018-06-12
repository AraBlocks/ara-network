const { defaults: dnsDefaults } = require('../dns')
const { defaults: dhtDefaults } = require('../dht')
const discovery = require('discovery-channel')
const extend = require('extend')
const crypto = require('ara-crypto')
const debug = require('debug')('ara:network:channel')

const defaults = {
  hash: false,
  dns: dnsDefaults,
  dht: dhtDefaults,

  get id() {
    return crypto.randomBytes(32)
  },
}

/**
 * Creates a discovery channelthat uses DNS
 * and DHT for peer discovery.
 * @public
 * @param {Object} opts
 * @return {Object}
 */
function createChannel(opts) {
  if (opts == null || typeof opts !== 'object') { opts = {} }
  debug('creating channel')
  opts = extend(true, {}, defaults, opts)
  const channel = discovery(opts)
  return channel
}

module.exports = {
  createChannel,
  defaults,
}
