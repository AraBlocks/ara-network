'use strict'

const discovery = require('discovery-channel')
const extend = require('extend')
const crypto = require('ara-crypto')
const debug = require('debug')('ara:network:channel')

const defaults = {
  dns: require('./dns').defaults,
  dht: require('./dht').defaults,
}

/**
 * Creates a discovery channelthat uses DNS
 * and DHT for peer discovery.
 * @public
 * @param {Object} opts
 * @return {Object}
 */
function createChannel(opts) {
  if (null == opts || 'object' != typeof opts) { opts = {} }
  opts = extend(true, {}, defaults, opts)
  const channel = discovery(opts)
  return channel
}

module.exports = {
  createChannel,
  defaults,
}
