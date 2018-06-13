const { createServer, createClient } = require('../dht')
const BitTorrentDHT = require('bittorrent-dht')
const { test } = require('ava')

test('dht - createServer - no opts', (t) => {
  const server = createServer()

  t.true(server instanceof BitTorrentDHT)
})

test('dht - createServer - opts', (t) => {
  const server = createServer({})

  t.true(server instanceof BitTorrentDHT)
})

test('dht - createClient - no opts', (t) => {
  const client = createClient()

  t.true(client instanceof BitTorrentDHT)
})

test('dht - createClient - opts', (t) => {
  const client = createClient({})

  t.true(client instanceof BitTorrentDHT)
})

