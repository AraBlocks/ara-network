const { defaults: dnsDefaults } = require('../dns')
const { defaults: dhtDefaults } = require('../dht')
const discovery = require('discovery-swarm')
const { warn } = require('ara-console')
const extend = require('extend')
const crypto = require('ara-crypto')
const rc = require('../rc')()

const defaults = Object.assign({
  hash: false,
  utp: true,
  tcp: true,
  dns: dnsDefaults,
  dht: dhtDefaults,

  get id() {
    return crypto.randomBytes(32)
  },
}, rc.network.discovery.swarm)

/**
 * Creates a discovery swarm server that uses DNS
 * and DHT for peer discovery and TCP/UDP(uTP) as
 * transports.
 *
 * @public
 * @param {Object} opts
 * @return {Object}
 */

function createSwarm(opts) {
  if (!opts || 'object' !== typeof opts) {
    // eslint-disable-next-line no-param-reassign
    opts = {}
  }

  if (!defaults.dns.server && !defaults.dht.bootstrap) {
    warn(`No default dht.bootstrap or dns.server value was found.` +
    `Be sure to use a local archiver | resolver.`)
  }

  // eslint-disable-next-line no-param-reassign
  opts = extend(true, {}, defaults, opts)
  const server = discovery(opts)
  return server
}

module.exports = {
  createSwarm,
  defaults,
}
