const { resolve } = require('path')
const extend = require('extend')
const rc = require('ara-runtime-configuration')

const defaults = () => ({
  network: {
    discovery: {
      channel: { },
      swarm: { },
    },

    dht: { },
    dns: { },
  }
})

module.exports = conf => rc(extend(true, {}, defaults(), conf))
