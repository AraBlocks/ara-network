'use strict'

const { info, warn, error } = require('ara-console')
const extend = require('extend')
const debug = require('debug')('ara:network:node:dns-discovery')
const dns = require('../dns')
const os = require('os')

/**
 * Configuration for a DNS discovery server.
 */
const conf = {
  workers: os.cpus().length,
  ports: [5300],
}

/**
 * DNS server instance
 */
let instance = null

/**
 * Starts a DNS discovery server node
 */
async function start(opts) {
  if (instance) { return false }
  if (opts && 'object' == typeof opts) {
    configure(opts)
  }

  info('dns-discovery:', "starting server")

  instance = dns.createServer(conf)
  instance.listen(conf.ports, onlisten)
  instance.on('error', onerror)
  return true

  function onlisten() {
    info("dns-discovery: Listening on ports (%s)", conf.ports)
  }

  function onerror(err) {
    if (err && 'EACCES' == err.code) {
      return debug("error:", err)
    } else if (true == conf.multicast) {
      if (err && 'EADDRINUSE' == err.code) {
        return debug("error:", err)
      }
    }
    throw err
  }
}

async function stop() {
  if (null == instance) { return false }
  instance.destroy(ondestroy)
  return true
  function ondestroy() {
    instance = null
    process.nextTick(() => process.exit(0))
  }
}

async function configure(opts) {
  return extend(true, conf, opts)
}

function getInstance() {
  return instance
}

module.exports = {
  start,
  stop,
  configure,
  getInstance,
}
