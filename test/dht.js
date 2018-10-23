const { createServer, createClient } = require('../dht')
const { test } = require('ava')

test('dht - createServer - no opts', (t) => {
  const server = createServer()

  t.true(Boolean(server.holepunch && server.lookup && server.announce))
})

test('dht - createServer - opts', (t) => {
  const server = createServer({})

  t.true(Boolean(server.holepunch && server.lookup && server.announce))
})

test('dht - createClient - no opts', (t) => {
  const client = createClient()

  t.true(Boolean(client.holepunch && client.lookup && client.announce))
})

test('dht - createClient - opts', (t) => {
  const client = createClient({})

  t.true(Boolean(client.holepunch && client.lookup && client.announce))
})

