const { resolve } = require('path')
const extend = require('extend')
const rc = require('ara-runtime-configuration')

const defaults = () => ({
  network: {
    identity: {
      root: resolve(rc().data.root, 'identities')
    },

    keyrings: {
      root: resolve(rc().data.root, 'keyrings')
    },

    discovery: {
      channel: { },
      swarm: { },
    },

    dht: { },
    dns: { },
  }
})

module.exports = conf => rc(extend(true, {}, defaults(), conf))
