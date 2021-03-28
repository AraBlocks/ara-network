const { createServer } = require('../dns')
const discovery = require('dns-discovery')
const test = require('ava')

test('dns - createServer - no opts', (t) => {
  const server = createServer()

  t.true(server instanceof discovery)
})

test('dns - createServer - opts', (t) => {
  const server = createServer({})

  t.true(server instanceof discovery)
})
