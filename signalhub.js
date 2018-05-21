'use strict'

const Server = require('signalhub/server')

function createServer(opts) {
  const server = Server(opts)
  return server
}

module.exports = {
  createServer
}
