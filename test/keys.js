const crypto = require('ara-crypto')
const keys = require('../keys')
const test = require('ava')

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
    combined: keys.unpack({ buffer: Buffer.concat([ packed.public, packed.secret ]) }),
    public: keys.unpack({ buffer: packed.public }),
    secret: keys.unpack({ buffer: packed.secret }),
  }

  t.true(0 == Buffer.compare(
    discoveryKey,
    unpacked.combined.discoveryKey
  ))

  t.true(0 == Buffer.compare(
    discoveryKey,
    unpacked.public.discoveryKey
  ))

  t.true(0 == Buffer.compare(
    discoveryKey,
    unpacked.secret.discoveryKey
  ))

  t.true(0 == Buffer.compare(
    publicKey,
    unpacked.combined.publicKey
  ))

  t.true(0 == Buffer.compare(
    publicKey,
    unpacked.public.publicKey
  ))

  t.true(0 == Buffer.compare(
    publicKey,
    unpacked.secret.publicKey
  ))

  t.true(0 == Buffer.compare(
    domain.secretKey,
    unpacked.combined.domain.secretKey
  ))

  t.true(0 == Buffer.compare(
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
  const domain = crypto.curve25519.keyPair()
  const netkeys = keys.generate0({publicKey, secretKey, secret})

  const unpacked = keys.unpack0({buffer: netkeys})

  t.true(0 == Buffer.compare(
    publicKey,
    unpacked.publicKey
  ))
})
