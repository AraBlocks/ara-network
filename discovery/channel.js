const { defaults: dnsDefaults } = require('../dns')
const { defaults: dhtDefaults } = require('../dht')
const discovery = require('discovery-channel')
const extend = require('extend')
const crypto = require('ara-crypto')

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
  if (!opts || 'object' !== typeof opts) {
    // eslint-disable-next-line no-param-reassign
    opts = {}
  }
  // eslint-disable-next-line no-param-reassign
  opts = extend(true, {}, defaults, opts)
  const channel = discovery(opts)
  return channel
}

module.exports = {
  createChannel,
  defaults,
}
