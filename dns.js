'use strict'

const discovery = require('dns-discovery')
const extend = require('extend')
const debug = require('debug')('ara:network:dns')

/**
 * Create a DNS discovery server
 * @public
 * @param {?(Object)} opts
 * @param {?(Boolean)} [opts.multicast = true]
 * @param {?(Boolean)} [opts.loopback = true]
 * @param {?(String)} [opts.domain = 'ara.local']
 * @param {?(Number)} [opts.limit = 10000]
 * @return {Object}
 */
function createServer(opts) {
  if (!opts || 'object' != typeof opts) { opts = {} }
  const server = discovery(configure(opts))
  server.on('listening', () => {
  })
  return server
}

function configure(opts) {
  return extend(true, {}, defaults(), opts)
}

function defaults() {
  return {
    multicast: true,
    loopback: true,
    domain: 'ara.local',
    limit: 10000,
  }
}

module.exports = {
  createServer
}
