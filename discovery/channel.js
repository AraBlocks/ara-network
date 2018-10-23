const { defaults: dnsDefaults } = require('../dns')
const { defaults: dhtDefaults } = require('../dht')
const discovery = require('@hyperswarm/discovery')
const extend = require('extend')
const crypto = require('ara-crypto')
const rc = require('../rc')()

const defaults = Object.assign({
  hash: false,
  domain: dnsDefaults.domain,
  get id() {
    return crypto.randomBytes(32)
  },
}, dhtDefaults, rc.network.discovery.channel)

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
