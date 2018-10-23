const { defaults: discoveryDefaults } = require('./channel')
const network = require('@hyperswarm/network')
const extend = require('extend')
const utp = require('utp-native')
const rc = require('../rc')()

const defaults = Object.assign(discoveryDefaults, rc.network.discovery.swarm)

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

  // eslint-disable-next-line no-param-reassign
  opts = extend(
    true, {}, defaults,
    opts,
    {
      // Note: baselining utp-native 1.7.3 due to instability of 2.x.x with hypercore
      socket: opts.socket || utp()
    }
  )
  const swarm = network(opts)
  return swarm
}

module.exports = {
  createSwarm,
  defaults,
}
