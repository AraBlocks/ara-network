const Server = require('signalhub/server')

/**
 * Create Signalhub Server (https://github.com/mafintosh/signalhub)
 *
 * @param  {Object} opts
 *
 * @return {Signalhub}
 */

function createServer(opts) {
  const server = Server(opts)
  return server
}

module.exports = {
  createServer
}
