const { Keyring } = require('../keyring')
const isBuffer = require('is-buffer')
const crypto = require('ara-crypto')
const keys = require('../keys')
const test = require('ava')
const ram = require('random-access-memory')
const ss = require('ara-secret-storage')

test('keys.pack() is a function', (t) => {
  t.true('function' === typeof keys.pack)
})

test('keys.pack0() is a function', (t) => {
  t.true('function' === typeof keys.pack0)
})

test('keys.pack() throws TypeError for bad input', (t) => {
  t.throws(() => keys.pack(), TypeError)
  t.throws(() => keys.pack(null), TypeError)
  t.throws(() => keys.pack(true), TypeError)
  t.throws(() => keys.pack(123), TypeError)
  t.throws(() => keys.pack(NaN), TypeError)
  t.throws(() => keys.pack(() => {}), TypeError)
})

test('keys.pack() throws TypeError for bad version ranges', (t) => {
  t.throws(() => keys.pack({ version: -1 }), TypeError)
  t.throws(() => keys.pack({ version: 0xfff }), TypeError)
})

test('keys.pack0() throws TypeError for bad input', (t) => {
  t.throws(() => keys.pack0(), TypeError)
  t.throws(() => keys.pack0(null), TypeError)
  t.throws(() => keys.pack0(true), TypeError)
  t.throws(() => keys.pack0(123), TypeError)
  t.throws(() => keys.pack0(NaN), TypeError)
  t.throws(() => keys.pack0(() => {}), TypeError)
})

test('keys.pack0(opts) correctly packs keys', (t) => {
  const { publicKey } = crypto.keyPair()
  const domain = crypto.curve25519.keyPair()
  const discoveryKey = crypto.blake2b(domain.secretKey)
  const packed = {
    public: keys.pack0({
      type: keys.PKX, discoveryKey, publicKey, domain
    }),

    secret: keys.pack0({
      type: keys.SKX, discoveryKey, publicKey, domain
    }),
  }

  t.true(1 + 1 + 32 + 32 + 32 === packed.public.length)
  t.true(1 + 1 + 32 + 32 + 32 === packed.secret.length)
  t.true(keys.PKX === packed.public[0])
  t.true(keys.SKX === packed.secret[0])
  t.true(keys.VERSION0 === packed.public[1])
  t.true(keys.VERSION0 === packed.secret[1])

  t.true(0 === Buffer.compare(
    discoveryKey,
    packed.public.slice(1 + 1, 1 + 1 + 32)
  ))

  t.true(0 === Buffer.compare(
    discoveryKey,
    packed.secret.slice(1 + 1, 1 + 1 + 32)
  ))

  t.true(0 === Buffer.compare(
    publicKey,
    packed.public.slice(1 + 1 + 32, 1 + 1 + 32 + 32)
  ))

  t.true(0 === Buffer.compare(
    publicKey,
    packed.secret.slice(1 + 1 + 32, 1 + 1 + 32 + 32)
  ))

  t.true(0 === Buffer.compare(
    domain.publicKey,
    packed.public.slice(1 + 1 + 32 + 32, 1 + 1 + 32 + 32 + 32)
  ))

  t.true(0 === Buffer.compare(
    domain.secretKey,
    packed.secret.slice(1 + 1 + 32 + 32, 1 + 1 + 32 + 32 + 32)
  ))
})

test('keys.unpack() is a function', (t) => {
  t.true('function' === typeof keys.unpack)
})

test('keys.unpack() throws TypeError for bad input', (t) => {
  t.throws(() => keys.unpack(), TypeError)
  t.throws(() => keys.unpack(null), TypeError)
  t.throws(() => keys.unpack(true), TypeError)
  t.throws(() => keys.unpack(123), TypeError)
  t.throws(() => keys.unpack(NaN), TypeError)
  t.throws(() => keys.unpack(() => {}), TypeError)
})

test('keys.unpack0() is a function', (t) => {
  t.true('function' === typeof keys.unpack0)
})

test('keys.unpack0() throws TypeError for bad input', (t) => {
  t.throws(() => keys.unpack0(), TypeError)
  t.throws(() => keys.unpack0(null), TypeError)
  t.throws(() => keys.unpack0(true), TypeError)
  t.throws(() => keys.unpack0(123), TypeError)
  t.throws(() => keys.unpack0(NaN), TypeError)
  t.throws(() => keys.unpack0(() => {}), TypeError)
})

test('keys.unpack0(opts) correctly unpacks keys', (t) => {
  const { publicKey } = crypto.keyPair()
  const domain = crypto.curve25519.keyPair()
  const discoveryKey = crypto.blake2b(domain.secretKey)
  const packed = {
    public: keys.pack0({
      type: keys.PKX, discoveryKey, publicKey, domain
    }),

    secret: keys.pack0({
      type: keys.SKX, discoveryKey, publicKey, domain
    }),
  }

  const unpacked = {
    combined: keys.unpack({
      buffer: Buffer.concat([ packed.public, packed.secret ])
    }),

    public: keys.unpack({ buffer: packed.public }),
    secret: keys.unpack({ buffer: packed.secret }),
  }

  t.true(0 === Buffer.compare(
    discoveryKey,
    unpacked.combined.discoveryKey
  ))

  t.true(0 === Buffer.compare(
    discoveryKey,
    unpacked.public.discoveryKey
  ))

  t.true(0 === Buffer.compare(
    discoveryKey,
    unpacked.secret.discoveryKey
  ))

  t.true(0 === Buffer.compare(
    publicKey,
    unpacked.combined.publicKey
  ))

  t.true(0 === Buffer.compare(
    publicKey,
    unpacked.public.publicKey
  ))

  t.true(0 === Buffer.compare(
    publicKey,
    unpacked.secret.publicKey
  ))

  t.true(0 === Buffer.compare(
    domain.secretKey,
    unpacked.combined.domain.secretKey
  ))

  t.true(0 === Buffer.compare(
    domain.secretKey,
    unpacked.secret.domain.secretKey
  ))
})

test('keys.generate() is a function', (t) => {
  t.true('function' === typeof keys.generate)
})

test('keys.generate() throws TypeError for bad input', (t) => {
  t.throws(() => keys.generate(), TypeError)
  t.throws(() => keys.generate(null), TypeError)
  t.throws(() => keys.generate(true), TypeError)
  t.throws(() => keys.generate(123), TypeError)
  t.throws(() => keys.generate(NaN), TypeError)
  t.throws(() => keys.generate(() => {}), TypeError)
})

test('keys.generate0() is a function', (t) => {
  t.true('function' === typeof keys.generate0)
})

test('keys.generate0() throws TypeError for bad input', (t) => {
  t.throws(() => keys.generate0(), TypeError)
  t.throws(() => keys.generate0(null), TypeError)
  t.throws(() => keys.generate0(true), TypeError)
  t.throws(() => keys.generate0(123), TypeError)
  t.throws(() => keys.generate0(NaN), TypeError)
  t.throws(() => keys.generate0(() => {}), TypeError)
})

test('keys.generate0() correctly generates packed keys', (t) => {
  const { publicKey, secretKey } = crypto.keyPair()
  const secret = crypto.randomBytes(16)
  const netkeys = keys.generate0({ publicKey, secretKey, secret })
  const unpacked = keys.unpack0({ buffer: netkeys })

  t.true(0 === Buffer.compare(
    publicKey,
    unpacked.publicKey
  ))
})

test('keys.encrypt0() is a function', (t) => {
  t.true('function' === typeof keys.encrypt0)
})

test('keys.encrypt0() throws TypeError for bad input', (t) => {
  t.throws(() => keys.encrypt0(), TypeError)
  t.throws(() => keys.encrypt0(null), TypeError)
  t.throws(() => keys.encrypt0(true), TypeError)
  t.throws(() => keys.encrypt0(123), TypeError)
  t.throws(() => keys.encrypt0(NaN), TypeError)
  t.throws(() => keys.encrypt0(() => {}), TypeError)
})

test('keys.encrypt0() encrypts public network keys', (t) => {
  const { publicKey, secretKey } = crypto.keyPair()
  const secret = crypto.randomBytes(16)
  const domain = crypto.curve25519.keyPair()
  const discoveryKey = crypto.blake2b(domain.secretKey)
  const buffer = keys.pack0({
    type: keys.PKX, discoveryKey, publicKey, domain
  })

  const encrypted = keys.encrypt0({ buffer, secretKey, secret })
  t.true('object' === typeof encrypted)

  const key = crypto.blake2b(crypto.blake2b(secret, 32), 16)
  const decrypted = ss.decrypt(encrypted, { key })

  t.true(0 === Buffer.compare(decrypted, buffer))
})

test('keys.encrypt0() encrypts secret network keys', (t) => {
  const { publicKey, secretKey } = crypto.keyPair()
  const secret = crypto.randomBytes(16)
  const domain = crypto.curve25519.keyPair()
  const discoveryKey = crypto.blake2b(domain.secretKey)
  const buffer = keys.pack0({
    type: keys.SKX, discoveryKey, publicKey, domain
  })

  const encrypted = keys.encrypt0({ buffer, secretKey, secret })
  t.true('object' === typeof encrypted)

  const key = crypto.blake2b(Buffer.concat([
    crypto.blake2b(secret, 32), secretKey
  ]), 16)

  const decrypted = ss.decrypt(encrypted, { key })

  t.true(0 === Buffer.compare(decrypted, buffer))
})

test('keys.decrypt0() is a function', (t) => {
  t.true('function' === typeof keys.decrypt0)
})

test('keys.decrypt0() throws TypeError for bad input', (t) => {
  t.throws(() => keys.decrypt0(), TypeError)
  t.throws(() => keys.decrypt0(null), TypeError)
  t.throws(() => keys.decrypt0(true), TypeError)
  t.throws(() => keys.decrypt0(123), TypeError)
  t.throws(() => keys.decrypt0(NaN), TypeError)
  t.throws(() => keys.decrypt0(() => {}), TypeError)
})

test('keys.decrypt0() decrypts public network keys', (t) => {
  const { publicKey, secretKey } = crypto.keyPair()
  const secret = crypto.randomBytes(16)
  const domain = crypto.curve25519.keyPair()
  const discoveryKey = crypto.blake2b(domain.secretKey)
  const buffer = keys.pack0({
    type: keys.PKX, discoveryKey, publicKey, domain
  })

  const encrypted = keys.encrypt0({ buffer, secretKey, secret })
  t.true('object' === typeof encrypted)

  const decrypted = keys.decrypt0(encrypted, { secret })

  t.true(0 === Buffer.compare(decrypted, buffer))
})

test('keys.decrypt0() decrypts secret network keys', (t) => {
  const { publicKey, secretKey } = crypto.keyPair()
  const secret = crypto.randomBytes(16)
  const domain = crypto.curve25519.keyPair()
  const discoveryKey = crypto.blake2b(domain.secretKey)
  const buffer = keys.pack0({
    type: keys.SKX, discoveryKey, publicKey, domain
  })

  const encrypted = keys.encrypt0({ buffer, secretKey, secret })
  t.true('object' === typeof encrypted)

  const decrypted = keys.decrypt0(encrypted, { secretKey, secret })

  t.true(0 === Buffer.compare(decrypted, buffer))
})

test('keys.keyPair0() is a function', (t) => {
  t.true('function' === typeof keys.keyPair0)
})

test('keys.keyPair() throws TypeError for bad input', (t) => {
  t.throws(() => keys.keyPair(), TypeError)
  t.throws(() => keys.keyPair(null), TypeError)
  t.throws(() => keys.keyPair(true), TypeError)
  t.throws(() => keys.keyPair(123), TypeError)
  t.throws(() => keys.keyPair(NaN), TypeError)
  t.throws(() => keys.keyPair(() => {}), TypeError)
  t.throws(() => keys.keyPair({ version: -1 }), TypeError)
  t.throws(() => keys.keyPair({ version: NaN }), TypeError)
  t.throws(() => keys.keyPair({ version: 0xff }), TypeError)
  t.throws(() => keys.keyPair({ version: 0xfff }), TypeError)
})

test('keys.keyPair0() throws TypeError for bad input', (t) => {
  t.throws(() => keys.keyPair0(), TypeError)
  t.throws(() => keys.keyPair0(null), TypeError)
  t.throws(() => keys.keyPair0(true), TypeError)
  t.throws(() => keys.keyPair0(123), TypeError)
  t.throws(() => keys.keyPair0(NaN), TypeError)
  t.throws(() => keys.keyPair0(() => {}), TypeError)
})

test('keys.keyPair0() should generate public keys', (t) => {
  const { publicKey, secretKey } = crypto.keyPair()
  const secret = crypto.randomBytes(16)
  const keyPair = keys.keyPair0({ publicKey, secretKey, secret })
  const buffer = keys.decrypt0(keyPair.publicKey, { secret })
  const unpacked = keys.unpack0({ buffer })
  t.true('object' === typeof keyPair.publicKey)
  t.true(0 === Buffer.compare(publicKey, unpacked.publicKey))
})

test('keys.keyPair0() should generate secret keys', (t) => {
  const { publicKey, secretKey } = crypto.keyPair()
  const secret = crypto.randomBytes(16)
  const keyPair = keys.keyPair0({ publicKey, secretKey, secret })
  const buffer = keys.decrypt0(keyPair.secretKey, { secretKey, secret })
  const unpacked = keys.unpack0({ buffer })
  t.true('object' === typeof keyPair.secretKey)
  t.true(isBuffer(unpacked.domain.secretKey))
})

test('keys.keyRing() is a function', (t) => {
  t.true('function' === typeof keys.keyRing)
})

test('keys.keyRing0() is a function', (t) => {
  t.true('function' === typeof keys.keyRing0)
})

test('keys.keyRing() throws on bad input', (t) => {
  t.throws(() => keys.keyRing(), TypeError)
  t.throws(() => keys.keyRing(null), TypeError)
  t.throws(() => keys.keyRing(ram()), TypeError)
  t.throws(() => keys.keyRing(ram(), { version: NaN }), TypeError)
  t.throws(() => keys.keyRing(ram(), { version: -1 }), TypeError)
  t.throws(() => keys.keyRing(ram(), { version: 0xff }), TypeError)
  t.throws(() => keys.keyRing(ram(), { version: 0xfff }), TypeError)
})

test('keys.keyRing0() throws on bad input', (t) => {
  t.throws(() => keys.keyRing0(), TypeError)
  t.throws(() => keys.keyRing0(null), TypeError)
  t.throws(() => keys.keyRing0(ram()), TypeError)
  t.throws(() => keys.keyRing0(ram(), null), TypeError)
  t.throws(() => keys.keyRing0(ram(), 1234), TypeError)
  t.throws(() => keys.keyRing0(ram(), true), TypeError)
})

test('keys.keyRing() returns a Keyring', async (t) => {
  const { publicKey, secretKey } = crypto.keyPair()
  const secret = crypto.randomBytes(64)
  const netkeys = keys.generate({ publicKey, secretKey, secret })
  const ring = keys.keyRing(ram(), { secret })
  t.true(ring instanceof Keyring)
  await ring.append('netkeys', netkeys)
  t.true(0 === Buffer.compare(netkeys, await ring.get('netkeys')))
})

test('keys.keyRing0() returns a Keyring', async (t) => {
  const { publicKey, secretKey } = crypto.keyPair()
  const secret = crypto.randomBytes(64)
  const netkeys = keys.generate0({ publicKey, secretKey, secret })
  const ring = keys.keyRing0(ram(), { secret })
  t.true(ring instanceof Keyring)
  await ring.append('netkeys', netkeys)
  t.true(0 === Buffer.compare(netkeys, await ring.get('netkeys')))
})

test.cb('keys.derive() is a function', (t) => {
  t.true('function' === typeof keys.derive)
  t.end()
})

test.cb('keys.derive0() is a function', (t) => {
  t.true('function' === typeof keys.derive0)
  t.end()
})

test.cb('keys.derive() throws on bad input', (t) => {
  t.throws(() => keys.derive(), TypeError)
  t.throws(() => keys.derive({}), TypeError)
  t.throws(() => keys.derive({ version: '' }), TypeError)
  t.throws(() => keys.derive({ version: null }), TypeError)
  t.throws(() => keys.derive({ version: true }), TypeError)
  t.throws(() => keys.derive({ version: 1234 }), TypeError)
  t.throws(() => keys.derive({ version: () => {} }), TypeError)
  t.throws(() => keys.derive({ version: -1 }), TypeError)
  t.throws(() => keys.derive({ version: 23 }), TypeError)
  t.throws(() => keys.derive({ version: NaN }), TypeError)
  t.throws(() => keys.derive({ version: 0xfff }), TypeError)
  t.end()
})

test.cb('keys.derive0() throws on bad input', (t) => {
  t.throws(() => keys.derive0(), TypeError)
  t.throws(() => keys.derive0(''), TypeError)
  t.throws(() => keys.derive0(null), TypeError)
  t.throws(() => keys.derive0(true), TypeError)
  t.throws(() => keys.derive0(1234), TypeError)
  t.throws(() => keys.derive0(() => {}), TypeError)
  t.throws(() => keys.derive0({}), TypeError)

  t.throws(() => keys.derive0({ secretKey: '' }), TypeError)
  t.throws(() => keys.derive0({ secretKey: null }), TypeError)
  t.throws(() => keys.derive0({ secretKey: true }), TypeError)
  t.throws(() => keys.derive0({ secretKey: 1234 }), TypeError)
  t.throws(() => keys.derive0({ secretKey: () => {} }), TypeError)
  t.throws(() => keys.derive0({ secretKey: Buffer.alloc(0) }), RangeError)
  t.throws(() => keys.derive0({ secretKey: Buffer.alloc(16) }), RangeError)

  t.throws(() => keys.derive0({
    secretKey: Buffer.alloc(32),
  }), TypeError)

  t.throws(() => keys.derive0({
    secretKey: Buffer.alloc(32),
    name: null
  }), TypeError)

  t.throws(() => keys.derive0({
    secretKey: Buffer.alloc(32),
    name: true
  }), TypeError)

  t.throws(() => keys.derive0({
    secretKey: Buffer.alloc(32),
    name: 1234
  }), TypeError)

  t.throws(() => keys.derive0({
    secretKey: Buffer.alloc(32),
    name: () => {}
  }), TypeError)

  t.throws(() => keys.derive0({
    secretKey: Buffer.alloc(32),
    name: ''
  }), RangeError)

  t.throws(() => keys.derive0({
    secretKey: Buffer.alloc(32),
    name: Buffer.alloc(0)
  }), RangeError)

  t.end()
})

test.cb('keys.derive0() returns a key pair', (t) => {
  const { secretKey } = crypto.ed25519.keyPair()
  const a = keys.derive0({ secretKey, name: 'a' })
  const b = keys.derive0({ secretKey, name: 'b' })

  t.true(isBuffer(a.publicKey))
  t.true(isBuffer(a.secretKey))

  t.true(isBuffer(b.publicKey))
  t.true(isBuffer(b.secretKey))

  t.true(0 !== Buffer.compare(a.publicKey, b.publicKey))
  t.true(0 !== Buffer.compare(a.secretKey, b.secretKey))

  t.end()
})
