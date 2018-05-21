'use strict'

const { info, warn, error } = require('ara-console')
const extend = require('extend')
const debug = require('debug')('ara:network:node:dns')
const dns = require('../dns')

/**
 * Configuration for a DNS server.
 */
const conf = {
  multicast: true,
  loopback: true,
  ports: [53, 5300],
}

/**
 * DNS server server
 */
let server = null

/**
 * Starts a DNS server node
 * @public
 * @param {Object} argv
 * @return Boolean
 */
async function start(argv) {
  if (server) { return false }

  info("dns: Starting server")

  server = dns.createServer(conf)
  server.on('error', onerror)
  server.on('traffic', ontraffic)
  server.on('secrets-rotated', onsecretsrotated)
  server.listen(conf.ports)

  for (const socket of server._sockets) {
    socket.on('listening', () => {
      const { port } = socket.address()
      info("dns: Listening on port %s", port)
    })
  }

  return true

  function onerror(err) {
    if (err && 'EACCES' == err.code) {
      const { port } = err
      conf.ports.splice(conf.ports.indexOf(port), 1)
      return debug("error:", err)
    } else if (true == conf.multicast) {
      if (err && 'EADDRINUSE' == err.code) {
        return debug("error:", err)
      }
    }
  }

  function ontraffic(type, details) {
    const { message, peer } = details
    info("dns: traffic: %s: %s: %s", type, message.type, message.opcode)
  }

  function onsecretsrotated() {
    info("dns: Secrets rotated")
  }
}

/**
 * Stops a DNS server node
 * @public
 * @return Boolean
 */
async function stop(argv) {
  if (null == server) { return false }
  warn("dns: Stopping server")
  server.destroy(ondestroy)
  return true
  function ondestroy() {
    server = null
  }
}

/**
 * Configures a DNS server node
 * @public
 * @param {Object} opts
 * @return Object
 */
async function configure(opts, program) {
  if (program) {
    program
      .option('port', {
        alias: 'p',
        type: 'number',
        describe: "Port or ports to listen on",
        default: conf.ports
      })
      .option('loopback', {
        type: 'boolean',
        default: conf.loopback,
        describe: "Loopback DNS discovery",
      })
      .option('multicast', {
        type: 'boolean',
        default: conf.multicast,
        describe: "Multicast DNS discovery",
      })
  }
  return extend(true, conf, opts)
}

/**
 * Returns reference to DNS server node
 * @public
 * @return Object
 */
async function getInstance(argv) {
  return server
}

module.exports = {
  getInstance,
  configure,
  start,
  stop,
}
