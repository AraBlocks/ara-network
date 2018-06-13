const { createChannel } = require('./channel')
const { createSwarm } = require('./swarm')

module.exports = {
  createServer: createSwarm,
  createChannel,
  createSwarm,
}
