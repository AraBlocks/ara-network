const { Handshake } = require('../secret-handshake')
const { test } = require('ava')
const crypto = require('ara-crypto')

const HEXCONST = 0xDEADBEEF

test('fails to create Handshake instance', (t) => {
  t.throws(() => { Handshake() }, TypeError)
})

test('creates Handshake instance', (t) => {
  const hand = new Handshake({})

  t.true(hand instanceof Handshake)
})

test('gets an initialization vector', (t) => {
  const hand = new Handshake({})

  const iv = hand.iv()

  t.is(iv.length, 16)
  t.true(iv instanceof Buffer)
})

test('gets key', (t) => {
  const discoveryKey = Buffer.alloc(32, HEXCONST)
  const hand = new Handshake({
    discoveryKey
  })

  const key = hand.key()
  const keySlice = discoveryKey.slice(0, 16)

  t.true(key.toString('hex') == keySlice.toString('hex'))
})

test('creates digest', (t) => {
  const discoveryKey = Buffer.alloc(32, HEXCONST)
  const networkPublicKey = Buffer.alloc(32, HEXCONST)
  const remotePublicKey = Buffer.alloc(32, HEXCONST)
  const clientSecretKey = Buffer.alloc(32, HEXCONST)

  const hand = new Handshake({
    discoveryKey,
    network: {
      publicKey: networkPublicKey
    },
    remote: {
      publicKey: remotePublicKey
    },
    client: {
      secretKey: clientSecretKey
    }
  })

  const buffers = []

  buffers.push(discoveryKey)
  buffers.push(networkPublicKey)
  buffers.push(remotePublicKey)
  buffers.push(clientSecretKey)

  const digest = crypto.blake2b(Buffer.concat(buffers))

  t.true(digest.toString('hex') == hand.digest().toString('hex'))
})

test('creates challenge', (t) => {
  const discoveryKey = Buffer.alloc(32, HEXCONST)
  const networkPublicKey = Buffer.alloc(32, HEXCONST)
  const remotePublicKey = Buffer.alloc(32, HEXCONST)
  const clientSecretKey = Buffer.alloc(32, HEXCONST)

  const hand = new Handshake({
    discoveryKey,
    network: {
      publicKey: networkPublicKey
    },
    remote: {
      publicKey: remotePublicKey
    },
    client: {
      secretKey: clientSecretKey
    }
  })

  const challenge = hand.challenge()

  t.true(challenge instanceof Buffer)
  t.notThrows(() => { JSON.parse(challenge.toString()) })
})

test('proof returns false if challenge can\'t be parsed', (t) => {
  const hand = new Handshake({})

  t.false(hand.proof(Buffer.from('a')))
})

test('proof returns false if challenge isn\'t a buffer', (t) => {
  const hand = new Handshake({})

  t.false(hand.proof(1))
})

test('proof returns true if compatiable', (t) => {
  const discoveryKey = Buffer.alloc(32, HEXCONST)
  const networkPublicKey = Buffer.alloc(32, HEXCONST)
  const remotePublicKey = Buffer.alloc(32, HEXCONST)
  const clientSecretKey = Buffer.alloc(32, HEXCONST)

  const hand = new Handshake({
    discoveryKey,
    network: {
      publicKey: networkPublicKey
    },
    remote: {
      publicKey: remotePublicKey
    },
    client: {
      secretKey: clientSecretKey
    }
  })

  const challenge = hand.challenge()

  t.true(hand.proof(challenge))
})
