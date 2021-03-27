/* eslint-disable object-curly-newline */
const isBuffer = require('is-buffer')
const crypto = require('ara-crypto')
const rimraf = require('rimraf')
const pify = require('pify')
const test = require('ava')
const keys = require('../keys')
const ram = require('random-access-memory')

const {
  computeSignature,
  computeRoots,
  Keyring,

  kEntryHeaderSize,
  kBoxHeaderSize,
  kSignatureSize,
} = require('../keyring')

test('kEntryHeaderSize is a number', (t) => {
  t.true('number' === typeof kEntryHeaderSize)
  t.true(8 + 8 === kEntryHeaderSize)
})

test('kBoxHeaderSize is a number', (t) => {
  t.true('number' === typeof kBoxHeaderSize)
  t.true(34 === kBoxHeaderSize)
})

test('kSignatureSize is a number', (t) => {
  t.true('number' === typeof kSignatureSize)
  t.true(64 === kSignatureSize)
})

test('Keyring(storage, opts) is a function', (t) => {
  t.true('function' === typeof Keyring)
})

test('computeSignature(storage, secretKey, cb) is a function', (t) => {
  t.true('function' === typeof computeSignature)
})

test('computeRoots(storage, cb) is a function', (t) => {
  t.true('function' === typeof computeRoots)
})

test('computeSignature(...) throws on bad input', async (t) => {
  const storage = ram()
  const key = crypto.randomBytes(64)

  await t.throws(computeSignature(), {instanceOf: TypeError})
  await t.throws(computeSignature(''), {instanceOf: TypeError})
  await t.throws(computeSignature(null), {instanceOf: TypeError})
  await t.throws(computeSignature(true), {instanceOf: TypeError})
  await t.throws(computeSignature(1234), {instanceOf: TypeError})

  await t.throws(computeSignature(storage), {instanceOf: TypeError})
  await t.throws(computeSignature(storage, ''), {instanceOf: TypeError})
  await t.throws(computeSignature(storage, null), {instanceOf: TypeError})
  await t.throws(computeSignature(storage, true), {instanceOf: TypeError})
  await t.throws(computeSignature(storage, 1234), {instanceOf: TypeError})
  await t.throws(computeSignature(storage, Buffer.alloc(0)), {instanceOf: TypeError})

  t.throws(() => computeSignature(storage, key, ''), {instanceOf: TypeError})
  t.throws(() => computeSignature(storage, key, { }), {instanceOf: TypeError})
  t.throws(() => computeSignature(storage, key, null), {instanceOf: TypeError})
  t.throws(() => computeSignature(storage, key, true), {instanceOf: TypeError})
  t.throws(() => computeSignature(storage, key, 1234), {instanceOf: TypeError})
})

test('computeRoots(storage, cb) throws on bad input', async (t) => {
  const storage = ram()

  await t.throws(computeRoots(), {instanceOf: TypeError})
  await t.throws(computeRoots(''), {instanceOf: TypeError})
  await t.throws(computeRoots(null), {instanceOf: TypeError})
  await t.throws(computeRoots(true), {instanceOf: TypeError})
  await t.throws(computeRoots(1234), {instanceOf: TypeError})

  t.throws(() => computeRoots(storage, ''), {instanceOf: TypeError})
  t.throws(() => computeRoots(storage, null), {instanceOf: TypeError})
  t.throws(() => computeRoots(storage, true), {instanceOf: TypeError})
  t.throws(() => computeRoots(storage, 1234), {instanceOf: TypeError})
  t.throws(() => computeRoots(storage, Buffer.alloc(0)), {instanceOf: TypeError})
})

test('computeRoots(storage, cb) rejects on bad input', async (t) => {
  const storage = ram()
  await t.throws(computeRoots(''), {instanceOf: TypeError})
  await t.throws(computeRoots(null), {instanceOf: TypeError})
  await t.throws(computeRoots(true), {instanceOf: TypeError})
  await t.throws(computeRoots(1234), {instanceOf: TypeError})
  await t.throws(computeRoots(storage), {instanceOf: Error})
})

test('Keyring(storage, opts) throws on bad input', (t) => {
  const noop = () => {}
  const open = noop
  const stat = noop
  const read = noop
  const write = noop

  const secret = crypto.randomBytes(64)
  const empty = Buffer.alloc(0)
  const nonce = crypto.randomBytes(32)
  const key = crypto.randomBytes(32)

  t.throws(() => Keyring(), {instanceOf: TypeError})
  t.throws(() => new Keyring(), {instanceOf: TypeError})
  t.throws(() => new Keyring(''), {instanceOf: TypeError})
  t.throws(() => new Keyring(null), {instanceOf: TypeError})
  t.throws(() => new Keyring(1234), {instanceOf: TypeError})
  t.throws(() => new Keyring(true), {instanceOf: TypeError})
  t.throws(() => new Keyring(() => ''), {instanceOf: TypeError})
  t.throws(() => new Keyring(() => null), {instanceOf: TypeError})
  t.throws(() => new Keyring(() => 1234), {instanceOf: TypeError})
  t.throws(() => new Keyring(() => true), {instanceOf: TypeError})
  t.throws(() => new Keyring(() => () => { }), {instanceOf: TypeError})
  t.throws(() => new Keyring({}), {instanceOf: TypeError})
  t.throws(() => new Keyring({ open }), {instanceOf: TypeError})
  t.throws(() => new Keyring({ open, stat }), {instanceOf: TypeError})
  t.throws(() => new Keyring({ open, stat, read }), {instanceOf: TypeError})
  t.throws(() => new Keyring({ open, stat, read, write }, ''), {instanceOf: TypeError})
  t.throws(() => new Keyring({ open, stat, read, write }, null), {instanceOf: TypeError})
  t.throws(() => new Keyring({ open, stat, read, write }, 1234), {instanceOf: TypeError})
  t.throws(() => new Keyring({ open, stat, read, write }, true), {instanceOf: TypeError})
  t.throws(() => new Keyring({ open, stat, read, write }, () => { }), {instanceOf: TypeError})
  t.throws(() => new Keyring({ open, stat, read, write }, {}), {instanceOf: TypeError})
  t.throws(() => new Keyring({ open, stat, read, write }, { nonce }), {instanceOf: TypeError})
  t.throws(() => new Keyring({ open, stat, read, write }, { key }), {instanceOf: TypeError})

  t.throws(() => new Keyring({
    open, stat, read, write
  }, {
    nonce,
    key: key.slice(0, -1)
  }), {instanceOf: TypeError})

  t.throws(() => new Keyring({
    open, stat, read, write
  }, {
    nonce: nonce.slice(0, 23),
    key,
  }), {instanceOf: TypeError})

  t.throws(() => new Keyring({
    open, stat, read, write
  }, {
    secret,
    nonce,
    key: key.slice(0, -1)
  }), {instanceOf: TypeError})

  t.throws(() => new Keyring({
    open, stat, read, write
  }, {
    secret,
    nonce: nonce.slice(0, 23),
    key,
  }), {instanceOf: TypeError})

  t.throws(() => new Keyring({
    open, stat, read, write
  }, {
    secret: empty
  }), {instanceOf: TypeError})
})

test('Keyring(storage, opts) instance', (t) => {
  const secret = crypto.randomBytes(64)
  const storage = ram()
  const keyring0 = new Keyring(storage, { secret })
  const keyring1 = new Keyring(storage, {
    encrypt() {},
    decrypt() {},
    unpack() {},
    pack() {},
    secret,
  })

  // key pairs
  t.true(isBuffer(keyring0.publicKey))
  t.true(isBuffer(keyring0.secretKey))
  t.true(32 === keyring0.publicKey.length)
  t.true(64 === keyring0.secretKey.length)

  t.true(storage === keyring0.storage)
  t.true(false === keyring0.isReady)
  t.true('function' === typeof keyring0.lock)

  // accessors
  t.true(isBuffer(keyring0.secret))
  t.true(64 === keyring0.secret.length)
  t.true(keyring0.readable)
  t.true(keyring0.writable)
  t.true(keyring0.statable)
  t.false(keyring0.packable)
  t.false(keyring0.unpackable)
  t.false(keyring0.encryptable)
  t.false(keyring0.decryptable)

  // key pairs
  t.true(isBuffer(keyring1.publicKey))
  t.true(isBuffer(keyring1.secretKey))
  t.true(32 === keyring1.publicKey.length)
  t.true(64 === keyring1.secretKey.length)

  t.true(storage === keyring1.storage)
  t.true(false === keyring1.isReady)
  t.true('function' === typeof keyring1.lock)

  // accessors
  t.true(isBuffer(keyring1.secret))
  t.true(64 === keyring1.secret.length)
  t.true(keyring1.readable)
  t.true(keyring1.writable)
  t.true(keyring1.statable)
  t.true(keyring1.packable)
  t.true(keyring1.unpackable)
  t.true(keyring1.encryptable)
  t.true(keyring1.decryptable)
})

test('Keyring#hash(name) computes a short hash for a keyring', (t) => {
  const expected = Buffer.from('c7bc40cae9400907', 'hex')
  const secret = Buffer.alloc(64).fill(1)
  const keyring = new Keyring(ram, { secret })
  const hash = keyring.hash('test')
  t.true(0 === Buffer.compare(expected, hash))
})

test.cb('Keyring#ready(cb) is called when ready', (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const keyring = new Keyring(ram, { secret })

  keyring.ready(() => {
    t.true(keyring.isReady)
    t.end()
  })
})

test('Keyring#ready(cb) throws on bad input', (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const keyring = new Keyring(ram, { secret })
  t.throws(() => keyring.ready(''), {instanceOf: TypeError})
  t.throws(() => keyring.ready([ ]), {instanceOf: TypeError})
  t.throws(() => keyring.ready({ }), {instanceOf: TypeError})
  t.throws(() => keyring.ready(null), {instanceOf: TypeError})
  t.throws(() => keyring.ready(true), {instanceOf: TypeError})
  t.throws(() => keyring.ready(1234), {instanceOf: TypeError})
})

test.cb('Keyring#ready(cb) throws on bad state', (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const keyring = new Keyring(ram, { secret })

  keyring.storage.close()
  keyring.ready(onready)

  function onready(err) {
    t.true(err instanceof Error)
    t.end()
  }
})

test('Keyring#ready() rejects on bad state', async (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const keyring = new Keyring(ram, { secret })

  keyring.storage.close()
  await t.throws(keyring.ready())
})

test('Keyring#ready() returns a promise', async (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const keyring = new Keyring(ram, { secret })
  await keyring.ready()
  t.true(keyring.isReady)
})

test.cb('Keyring#proof(cb) returns an empty proof for new instance.', (t) => {
  t.plan(2)
  const secret = Buffer.alloc(64).fill(1)
  const keyring = new Keyring(ram, { secret })
  keyring.proof((err, proof) => {
    t.true(null === err)
    t.true(null === proof)
    t.end()
  })
})

test.cb('Keyring#proof(cb) returns a computed proof.', (t) => {
  t.plan(3)
  const key = Buffer.alloc(64).fill(2)
  const secret = Buffer.alloc(64).fill(1)
  const keyring = new Keyring(ram(), { secret })
  const expected = Buffer.from(
    '02855e4b1dd1c0707e574fa4fc89aaa6e6c72e4c7777c99e8640a983a310c423' +
    '839821106a46091ccd712fc56c8d113dfd91aec43867bb0916941c41a8290c0e',
    'hex'
  )

  keyring.ready(onready)

  function onready() {
    keyring.append('test', key, onappend)
  }

  function onappend(err) {
    t.true(null === err)
    keyring.proof(onproof)
  }

  function onproof(err, proof) {
    t.true(null === err)
    t.true(0 === Buffer.compare(proof, expected))
    t.end()
  }
})

test('Keyring#proof(cb) throws on bad input.', (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const keyring = new Keyring(ram, { secret })
  t.throws(() => keyring.proof(''), {instanceOf: TypeError})
  t.throws(() => keyring.proof([ ]), {instanceOf: TypeError})
  t.throws(() => keyring.proof({ }), {instanceOf: TypeError})
  t.throws(() => keyring.proof(null), {instanceOf: TypeError})
  t.throws(() => keyring.proof(true), {instanceOf: TypeError})
  t.throws(() => keyring.proof(1234), {instanceOf: TypeError})
})

test('Keyring#proof() returns a promise', async (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const keyring = new Keyring(ram, { secret })
  const proof = await keyring.proof()
  t.true(null === proof)
})

test.cb('Keyring#stat(cb) returns size 0 for empty instance.', (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const keyring = new Keyring(ram(), { secret })
  keyring.stat(onstat)
  function onstat(err, stat) {
    t.true(null === err)
    t.true(null !== stat)
    t.true('object' === typeof stat)
    t.true(0 === stat.size)
    t.end()
  }
})

test.cb('Keyring#stat(cb) returns 0 for non-stat storage.', (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const storage = {
    stat: null,
    statable: false,
    open(cb) { cb(null) },
    read(o, s, cb) { cb(null) },
    write(o, b, cb) { cb(null) }
  }

  const keyring = new Keyring(storage, { secret })
  keyring.append('test', crypto.randomBytes(32), onappend)

  function onappend() {
    keyring.stat(onstat)
  }

  function onstat(err, stat) {
    t.true(null === err)
    t.true(null !== stat)
    t.true('object' === typeof stat)
    t.true(0 === stat.size)
    t.end()
  }
})

test.cb('Keyring#stat(cb) returns storage length if not statable.', (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const storage = ram()
  storage.stat = null
  storage.statable = false
  const keyring = new Keyring(storage, { secret })
  keyring.append('test', crypto.randomBytes(32), onappend)

  function onappend(err) {
    t.true(null === err)
    keyring.stat(onstat)
  }

  function onstat(err, stat) {
    t.true(null === err)
    t.true(null !== stat)
    t.true('object' === typeof stat)
    t.true(storage.length === stat.size)
    t.end()
  }
})

test('Keyring#stat() returns a promise', async (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const storage = ram()
  const keyring = new Keyring(storage, { secret })
  const stat = await keyring.stat()
  t.true('object' === typeof stat)
  t.true('number' === typeof stat.size)
  t.true(storage.length === stat.size)
})

test.cb('Keyring#stat(cb) throws on bad storage state.', (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const storage = ram()
  const keyring = new Keyring(storage, { secret })

  // modify _stat after 'ready'
  keyring.ready(() => {
    storage._stat = (req) => {
      req.callback(new Error('error'))
    }

    keyring.stat(onstat)
  })

  function onstat(err, stat) {
    t.true(err instanceof Error)
    t.true(undefined === stat)
    t.end()
  }
})

test.cb('Keyring#append(name, key, cb) appends a key to instance.', (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const storage = ram()
  const keyring = new Keyring(storage, { secret })
  const key = crypto.randomBytes(32)

  keyring.once('signature', onsignature)
  keyring.append('test', key, onappend)

  function onappend(err, entry) {
    t.true(null === err)
    t.true(null !== entry)
    t.true('object' === typeof entry)
    t.true('string' === typeof entry.name)
    t.true('test' === entry.name)
    t.true(isBuffer(entry.hash))
    t.true(0 === Buffer.compare(keyring.hash(entry.name), entry.hash))
  }

  function onsignature(signature) {
    t.true(isBuffer(signature))
    t.end()
  }
})

test.cb('Keyring#append(name, key, cb) throws on bad storage state.', (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const storage = ram()
  delete storage.length
  const keyring = new Keyring(storage, { secret })
  const key = crypto.randomBytes(32)

  keyring.append('test', key, onappend)

  function onappend(err, entry) {
    t.true(err instanceof Error)
    t.true(undefined === entry)
    t.end()
  }
})

test.cb('Keyring#append(name, key, cb) throws on bad storage state.', (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const storage = ram()
  const keyring = new Keyring(storage, { secret })
  const key = crypto.randomBytes(32)

  keyring.append('test', key, onappend)

  storage._write = (req) => {
    req.callback(new Error())
  }

  function onappend(err, entry) {
    t.true(err instanceof Error)
    t.true(undefined === entry)
    t.end()
  }
})

test('Keyring#append(name, key, cb) throws if not writable.', async (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const storage = ram()
  const keyring = new Keyring(storage, { secret, readonly: true })
  const key = crypto.randomBytes(32)

  await t.throws(keyring.append('test', key), {instanceOf: TypeError})
  await new Promise((resolve) => {
    keyring.append('test', key, (err) => {
      t.true(null !== err)
      resolve()
    })
  })
})

test('Keyring#append(...) throws in bad storage state.', async (t) => {
  const secret = Buffer.alloc(64).fill(1)
  const storage = ram()
  const keyring = new Keyring(storage, { secret })
  const key = crypto.randomBytes(32)
  await keyring.ready()
  storage.close()
  await t.throws(keyring.append('test', key), Error)
})

test.cb('Keyring#get(name, cb) gets a key by name', (t) => {
  const key = crypto.randomBytes(64)
  const name = 'test'
  const secret = crypto.randomBytes(64)
  const keyring = new Keyring(ram(), { secret })

  keyring.ready(onready)

  function onready() {
    keyring.append(name, key, onappend)
  }

  function onappend(err) {
    t.true(null === err)
    keyring.get(name, onget)
  }

  function onget(err, result) {
    t.true(null === err)
    t.true(0 === Buffer.compare(key, result))
    t.end()
  }
})

test('Keyring(storage, opts) emits ready for empty instance', async (t) => {
  const secret = crypto.randomBytes(64)
  const keyring = new Keyring(ram(), { secret })
  let missing = 3

  t.plan(missing + 1)

  keyring.once('ready', onready)
  await keyring.ready(onready)

  t.true(Boolean(missing--))
  t.true(keyring.isReady)

  function onready() {
    t.true(Boolean(missing--))
  }
})

test('Keyring(storage, opts) emits ready for existing instance', async (t) => {
  const key = crypto.randomBytes(64)
  const secret = crypto.randomBytes(64)
  const storage = ram()
  const keyring = new Keyring(storage, { secret })
  await keyring.append('test', key)

  const keyringx = new Keyring(storage, { secret })
  let missing = 3

  t.plan(missing + 1)

  keyringx.once('ready', onready)
  await keyringx.ready(onready)
  t.true(Boolean(missing--))
  t.true(keyring.isReady)

  function onready() {
    t.true(Boolean(missing--))
  }
})

test('Keyring(...) simple test', async (t) => {
  // eslint-disable-next-line no-shadow
  const keys = {
    alpha: crypto.ed25519.keyPair(Buffer.alloc(32).fill('alpha')),
    beta: crypto.ed25519.keyPair(Buffer.alloc(32).fill('beta')),
    gamma: crypto.curve25519.keyPair(Buffer.alloc(32).fill('gamma'))
  }

  const path = './test-keyring'
  await pify(rimraf)(path)

  const secret = Buffer.alloc(64).fill('secret')
  const keyring = new Keyring(path, { secret })
  const keyringx = new Keyring(keyring.storage, { secret })

  await keyring.ready()

  await keyring.append('alpha', keys.alpha.secretKey)
  await keyring.append('beta', keys.beta.secretKey)
  await keyring.append('gamma', keys.gamma.secretKey)

  t.true(0 === Buffer.compare(
    await keyring.get('gamma'),
    keys.gamma.secretKey
  ))

  t.true(0 === Buffer.compare(
    await keyring.get('alpha'),
    await keyringx.get('alpha'),
  ))

  t.true(0 === Buffer.compare(
    await keyring.get('beta'),
    await keyringx.get('beta'),
  ))

  t.true(0 === Buffer.compare(
    await keyring.get('gamma'),
    await keyringx.get('gamma'),
  ))

  await pify(rimraf)(path)
})

test('Keyring(...) with network keys', async (t) => {
  const secret = crypto.randomBytes(64)
  const { publicKey, secretKey } = crypto.keyPair()
  const networkKeys = keys.generate({ publicKey, secretKey, secret })
  const storage = ram()
  const keyring = new Keyring(storage, {
    secret, decrypt, encrypt
  })

  await keyring.append('testnet', networkKeys)

  t.true(0 === Buffer.compare(
    networkKeys,
    await keyring.get('testnet')
  ))

  const buffer = await keyring.get('testnet')
  const unpacked = keys.unpack({ buffer })
  const expected = keys.unpack({ buffer: networkKeys })

  t.true(0 === Buffer.compare(
    unpacked.discoveryKey,
    expected.discoveryKey
  ))

  t.true(0 === Buffer.compare(
    unpacked.publicKey,
    expected.publicKey
  ))

  t.true(0 === Buffer.compare(
    unpacked.domain.publicKey,
    expected.domain.publicKey
  ))

  t.true(0 === Buffer.compare(
    unpacked.domain.secretKey,
    expected.domain.secretKey
  ))

  function decrypt(buf, name, k) {
    return keys.decrypt(JSON.parse(buf), k)
  }

  function encrypt(buf, name, k) {
    return Buffer.from(JSON.stringify(keys.encrypt({
      secretKey: k.secretKey,
      secret: k.secret,
      buffer: buf,
    })))
  }
})
