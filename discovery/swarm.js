'use strict'

const discovery = require('discovery-swarm')
const extend = require('extend')
const crypto = require('ara-crypto')
const debug = require('debug')('ara:network:discovery')

const defaults = {
  hash: false,
  utp: true,
  tcp: true,
  dns: require('../dns').defaults,
  dht: require('../dht').defaults,

  get id() {
    return crypto.randomBytes(32)
  },
}

/**
 * Creates a discovery swarm server that uses DNS
 * and DHT for peer discovery and TCP/UDP(uTP) as
 * transports.
 * @public
 * @param {Object} opts
 * @return {Object}
 */
function createSwarm(opts) {
  if (null == opts || 'object' != typeof opts) { opts = {} }
  opts = extend(true, {}, defaults, opts)
  const server = discovery(opts)
  return server
}

module.exports = {
  createSwarm,
  defaults,
}
