const { createServer, createChannel, createSwarm } = require('../discovery')
const discoveryChannel = require('discovery-channel')
const discoverySwarm = require('discovery-swarm')
const test = require('ava')

test('discovery - createSwarm - no opts', (t) => {
  const server = createSwarm()

  t.true(server instanceof discoverySwarm)
})

test('discovery - createSwarm - opts', (t) => {
  const server = createSwarm({})

  t.true(server instanceof discoverySwarm)
})

test('discovery - createChannel - no opts', (t) => {
  const client = createChannel()

  t.true(client instanceof discoveryChannel)
})

test('discovery - createChannel - opts', (t) => {
  const client = createChannel({})

  t.true(client instanceof discoveryChannel)
})

test('discovery - createServer - no opts', (t) => {
  const server = createServer()

  t.true(server instanceof discoverySwarm)
})

test('discovery - createServer - opts', (t) => {
  const server = createServer({})

  t.true(server instanceof discoverySwarm)
})
