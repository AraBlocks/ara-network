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

test('discovery - join channel - no opts', (t) => {
  const channel = createChannel({})
  const key = 'key'
  t.true(Boolean(channel.join && channel.leave))

  channel.join(key)
  t.true(channel._topics.has(key.toString('hex')))

  channel.leave(key)
  t.false(channel._topics.has(key.toString('hex')))
})

test('discovery - join channel - opts', (t) => {
  const channel = createChannel({})
  const key = Buffer.from('key', 'hex')
  t.true(Boolean(channel.join && channel.leave))

  channel.join(key, { announce: true })
  t.true(channel._topics.has(key.toString('hex')))
  t.true(Boolean(channel._topics.get(key.toString('hex')).announce))

  channel.leave(key)
  t.false(channel._topics.has(key.toString('hex')))
})

test('discovery - createServer - no opts', (t) => {
  const server = createServer()

  t.true(Boolean(server.join && server.leave))
})

test('discovery - createServer - opts', (t) => {
  const server = createServer({})

  t.true(Boolean(server.join && server.leave))
})
