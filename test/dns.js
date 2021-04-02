const discovery = require('dns-discovery')
const test = require('ava')

const { createServer } = require('../dns')

test('dns - createServer - no opts', (t) => {
  const server = createServer()

  t.true(server instanceof discovery)
})

test('dns - createServer - opts', (t) => {
  const server = createServer({})

  t.true(server instanceof discovery)
})
