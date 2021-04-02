const isBuffer = require('is-buffer')
const crypto = require('ara-crypto')
const test = require('ava')
const pump = require('pump')

const { Handshake, State } = require('../handshake')

test('Handshake is a function', (t) => {
  t.true('function' === typeof Handshake)
})

test('State is a function', (t) => {
  t.true('function' === typeof State)
})

test('Handshake simple', async (t) => {
  t.plan(31)

  // 3
  t.throws(() => new Handshake(), { instanceOf: TypeError })
  t.throws(() => new Handshake(null), { instanceOf: TypeError })
  t.throws(() => new Handshake(true), { instanceOf: TypeError })

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

    t.true(State.HELLO === remote.state.phase)
    t.true(State.HELLO === client.state.phase)

    remote.once('hello', (hello) => {
      // console.log('remote hello')
      // 3
      t.true('object' === typeof hello)
      t.true(isBuffer(hello.publicKey))
      t.true(0 === Buffer.compare(
        client.state.session.local.publicKey,
        hello.publicKey
      ))

      t.true(State.AUTH === remote.state.phase)
      t.true(remote.hello())
    })

    client.once('hello', (hello) => {
      // console.log('client hello')
      // 3
      t.true('object' === typeof hello)
      t.true(isBuffer(hello.publicKey))
      t.true(0 === Buffer.compare(
        remote.state.session.local.publicKey,
        hello.publicKey
      ))

      t.true(State.AUTH === client.state.phase)
      t.true(client.auth())
    })

    client.once('auth', (auth) => {
      // console.log('client auth')
      // 3
      t.true('object' === typeof auth)
      t.true(isBuffer(auth.publicKey))
      t.true(isBuffer(auth.signature))
    })

    remote.once('auth', (auth) => {
      // console.log('remote auth')
      // 3
      t.true('object' === typeof auth)
      t.true(isBuffer(auth.publicKey))
      t.true(isBuffer(auth.signature))
    })

    client.once('okay', (signature) => {
      // console.log('client okay')
      // 1
      t.true(isBuffer(signature))

      writer = client.createWriteStream()

      setTimeout(() => writer.write(message), 1000)

      client.createReadStream().once('data', (chunk) => {
        // console.log('client data')
        // 1
        t.true(0 === Buffer.compare(chunk, message))
        client.end()
      })
    })

    remote.once('okay', (signature) => {
      // console.log('remote okay')
      // 1
      t.true(isBuffer(signature))

      reader = remote.createReadStream()
      reader.once('data', (chunk) => {
        // console.log('remote data')
        // 1
        t.true(0 === Buffer.compare(chunk, message))
        remote.createWriteStream().write(message)
      })

      client.once('end', () => {
        // console.log('client end')
        remote.end()
        client.destroy()
        remote.destroy()
        resolve()
      })
    })

    // client.pipe(remote).pipe(client)
    pump(client, remote, client)

    // 1
    t.true(client.hello())
  })
})
