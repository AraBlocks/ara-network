const { createServer, createChannel, createSwarm } = require('../discovery')
const { test } = require('ava')

test('discovery - createSwarm - no opts', (t) => {
  const server = createSwarm()

  t.true(Boolean(server.join && server.leave))
})

test('discovery - createSwarm - opts', (t) => {
  const server = createSwarm({})

  t.true(Boolean(server.join && server.leave))
})

test('discovery - createChannel - no opts', (t) => {
  const client = createChannel()

  t.true(Boolean(client.lookup && client.announce))
})

test('discovery - createChannel - opts', (t) => {
  const client = createChannel({})

  t.true(Boolean(client.lookup && client.announce))
})

test('discovery - createServer - no opts', (t) => {
  const server = createServer()

  t.true(Boolean(server.join && server.leave))
})

test('discovery - createServer - opts', (t) => {
  const server = createServer({})

  t.true(Boolean(server.join && server.leave))
})
