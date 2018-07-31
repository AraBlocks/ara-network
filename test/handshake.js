const { Handshake, State } = require('../handshake')
const isBuffer = require('is-buffer')
const crypto = require('ara-crypto')
const pump = require('pump')
const test = require('ava')

test('Handshake is a function', (t) => {
  t.true('function' === typeof Handshake)
})

test('State is a function', (t) => {
  t.true('function' === typeof State)
})

test('Handshake simple', async (t) => {
  t.plan(3 + 1 + 2 + 2 + 3 + 3 + 3 + 1 + 3 + 1 + 1 + 1)

  // 3
  t.throws(() => new Handshake(), TypeError)
  t.throws(() => new Handshake(null), TypeError)
  t.throws(() => new Handshake(true), TypeError)

  // 1
  t.true('string' === typeof Handshake.VERSION)

  const bob = crypto.keyPair()
  const alice = crypto.keyPair()
  const secret = crypto.randomBytes(16)

  const s = crypto.blake2b(secret)
  const bs = crypto.blake2b(bob.secretKey)
  const seed = crypto.blake2b(Buffer.concat([ s, bs ]))
  const domain = crypto.curve25519.keyPair(seed)

  const client = new Handshake({
    secret,
    publicKey: alice.publicKey,
    secretKey: alice.secretKey,
    remote: { publicKey: bob.publicKey },
    domain: { publicKey: domain.publicKey }
  })

  // 2
  t.true(client.isAlice)
  t.true('object' === typeof client.state)

  const remote = new Handshake({
    secret,
    publicKey: bob.publicKey,
    secretKey: bob.secretKey,
    domain: { secretKey: domain.secretKey }
  })

  // 2
  t.true(remote.isBob)
  t.true('object' === typeof remote.state)

  await new Promise((resolve) => {
    const message = Buffer.from('hello')
    let reader = null
    let writer = null

    remote.once('hello', (hello) => {
      // 3
      t.true('object' === typeof hello)
      t.true(isBuffer(hello.publicKey))
      t.true(0 === Buffer.compare(
        client.state.session.local.publicKey,
        hello.publicKey
      ))
    })

    client.once('hello', (hello) => {
      // 3
      t.true('object' === typeof hello)
      t.true(isBuffer(hello.publicKey))
      t.true(0 === Buffer.compare(
        remote.state.session.local.publicKey,
        hello.publicKey
      ))

      client.auth()
    })

    client.once('auth', (auth) => {
      // 3
      t.true('object' === typeof auth)
      t.true(isBuffer(auth.publicKey))
      t.true(isBuffer(auth.signature))
    })

    client.once('okay', (signature) => {
      // 1
      t.true(isBuffer(signature))

      writer = client.createWriteStream()
    })

    remote.once('auth', (auth) => {
      // 3
      t.true('object' === typeof auth)
      t.true(isBuffer(auth.publicKey))
      t.true(isBuffer(auth.signature))
    })

    remote.once('okay', (signature) => {
      // 1
      t.true(isBuffer(signature))

      reader = client.createReadStream()

      reader.once('data', (chunk) => {
        // 1
        t.true(0 === Buffer.compare(chunk, message))
        remote.createWriteStream().write(message)
      })

      client.createReadStream().once('data', (chunk) => {
        // 1
        t.true(0 === Buffer.compare(chunk, message))
        resolve()
      })

      writer.write(message)
    })

    pump(client, remote, client)

    client.hello()
  })
})
