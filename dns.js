const discovery = require('dns-discovery')
const extend = require('extend')
// const debug = require('debug')('ara:network:dns')

const defaults = {
  multicast: true,
  loopback: true,
  domain: 'ara.local',
  limit: 10000,
}

/**
 * Create a DNS discovery server
 *
 * @public
 * @param {Object} opts
 * @param {Boolean} [opts.multicast = true]
 * @param {Boolean} [opts.loopback = true]
 * @param {String} [opts.domain = 'ara.local']
 * @param {Number} [opts.limit = 10000]
 * @return {Object}
 */

function createServer(opts) {
  if (!opts || 'object' !== typeof opts) {
    // eslint-disable-next-line no-param-reassign
    opts = {}
  }
  // eslint-disable-next-line no-param-reassign
  opts = extend(true, {}, defaults, opts)
  const server = discovery(opts)
  return server
}

module.exports = {
  createServer,
  defaults,
}
