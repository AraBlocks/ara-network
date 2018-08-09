const { resolve } = require('path')
const extend = require('extend')
const rc = require('ara-runtime-configuration')

const defaults = () => ({
  network: {
    secrets: {
      root: resolve(rc().data.root, 'secrets')
    },

    keyrings: {
      root: resolve(rc().data.root, 'keyrings')
    }
  }
})

module.exports = conf => rc(extend(true, {}, defaults(), conf))
