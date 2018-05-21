'use strict'

const { info, warn, error } = require('ara-console')
const extend = require('extend')
const debug = require('debug')('ara:network:node:dht')
const dht = require('../../dht')

const conf = { port: 6881 }

let server = null

async function start(argv) {
  if (server) { return false }

  server = dht.createServer(conf)
  server.listen(conf.port)
  server.on('error', onerror)
  server.on('close', onclose)
  server.on('listening', onlistening)

  return true

  function onerror(err) {
    warn("dht: error:", err.message)
    debug("error:", err)
  }

  function onclose() {
    warn("dht: Closed")
  }

  function onlistening() {
    const { port } = server.address()
    info("dht: Listening on port %s", port)
  }
}

async function stop(argv) {
  if (null == server) { return false }
  warn("dht: Stopping server")
  server.close(onclose)
  return true
  function onclose() {
    server = null
  }
}

async function configure(opts, program) {
  if (program) {
    const { argv } = program
    if (argv.port) {
      opts.port = argv.port
    }
  }
  return extend(true, conf, opts)
}

async function getInstance(argv) {
  return server
}

module.exports = {
  getInstance,
  configure,
  start,
  stop,
}
