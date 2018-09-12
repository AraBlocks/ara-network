const discovery = require('dns-discovery')
const extend = require('extend')
const rc = require('./rc')()

const defaults = Object.assign({
  multicast: true,
  interval: 1 * 60 * 1000,
  loopback: true,
  domain: 'ara.local',
  limit: 10000,
}, rc.network.dns)

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
