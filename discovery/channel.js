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
 * Creates a discovery channel that uses DNS
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
  const channel = Object.assign(discovery(opts), { join, leave })

  function join(key, options = {}) {
    if (!this._topics) {
      this._topics = new Map()
    }
    this.leave(key)

    const hex = key.toString('hex')

    const topic = options.announce
      ? this.announce(key, options)
      : this.lookup(key)

    topic.on('peer', peer => this.emit('peer', peer))
    topic.on('update', () => this.emit('update'))

    this._topics.set(hex, topic)
  }

  function leave(key) {
    if (!this._topics) return

    const hex = key.toString('hex')
    const prev = this._topics.get(hex)
    if (prev) {
      prev.destroy()
      this._topics.delete(hex)
    }
  }

  return channel
}

module.exports = {
  createChannel,
  defaults,
}
