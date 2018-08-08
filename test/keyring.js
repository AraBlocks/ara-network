/* eslint-disable object-curly-newline */
const isBuffer = require('is-buffer')
const crypto = require('ara-crypto')
const rimraf = require('rimraf')
const pify = require('pify')
const test = require('ava')
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

  await t.throws(computeSignature(), TypeError)
  await t.throws(computeSignature(''), TypeError)
  await t.throws(computeSignature(null), TypeError)
  await t.throws(computeSignature(true), TypeError)
  await t.throws(computeSignature(1234), TypeError)

  await t.throws(computeSignature(storage), TypeError)
  await t.throws(computeSignature(storage, ''), TypeError)
  await t.throws(computeSignature(storage, null), TypeError)
  await t.throws(computeSignature(storage, true), TypeError)
  await t.throws(computeSignature(storage, 1234), TypeError)
  await t.throws(computeSignature(storage, Buffer.alloc(0)), TypeError)

  t.throws(() => computeSignature(storage, key, ''), TypeError)
  t.throws(() => computeSignature(storage, key, { }), TypeError)
  t.throws(() => computeSignature(storage, key, null), TypeError)
  t.throws(() => computeSignature(storage, key, true), TypeError)
  t.throws(() => computeSignature(storage, key, 1234), TypeError)
})

test('computeRoots(storage, cb) throws on bad input', async (t) => {
  const storage = ram()

  await t.throws(computeRoots(), TypeError)
  await t.throws(computeRoots(''), TypeError)
  await t.throws(computeRoots(null), TypeError)
  await t.throws(computeRoots(true), TypeError)
  await t.throws(computeRoots(1234), TypeError)

  t.throws(() => computeRoots(storage, ''), TypeError)
  t.throws(() => computeRoots(storage, null), TypeError)
  t.throws(() => computeRoots(storage, true), TypeError)
  t.throws(() => computeRoots(storage, 1234), TypeError)
  t.throws(() => computeRoots(storage, Buffer.alloc(0)), TypeError)
})

test('computeRoots(storage, cb) rejects on bad input', async (t) => {
  const storage = ram()
  await t.throws(computeRoots(''), TypeError)
  await t.throws(computeRoots(null), TypeError)
  await t.throws(computeRoots(true), TypeError)
  await t.throws(computeRoots(1234), TypeError)
  await t.throws(computeRoots(storage), Error)
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

  t.throws(() => Keyring(), TypeError)
  t.throws(() => new Keyring(), TypeError)
  t.throws(() => new Keyring(''), TypeError)
  t.throws(() => new Keyring(null), TypeError)
  t.throws(() => new Keyring(1234), TypeError)
  t.throws(() => new Keyring(true), TypeError)
  t.throws(() => new Keyring(() => ''), TypeError)
  t.throws(() => new Keyring(() => null), TypeError)
  t.throws(() => new Keyring(() => 1234), TypeError)
  t.throws(() => new Keyring(() => true), TypeError)
  t.throws(() => new Keyring(() => () => { }), TypeError)
  t.throws(() => new Keyring({}), TypeError)
  t.throws(() => new Keyring({ open }), TypeError)
  t.throws(() => new Keyring({ open, stat }), TypeError)
  t.throws(() => new Keyring({ open, stat, read }), TypeError)
  t.throws(() => new Keyring({ open, stat, read, write }, ''), TypeError)
  t.throws(() => new Keyring({ open, stat, read, write }, null), TypeError)
  t.throws(() => new Keyring({ open, stat, read, write }, 1234), TypeError)
  t.throws(() => new Keyring({ open, stat, read, write }, true), TypeError)
  t.throws(() => new Keyring({ open, stat, read, write }, () => { }), TypeError)
  t.throws(() => new Keyring({ open, stat, read, write }, {}), TypeError)
  t.throws(() => new Keyring({ open, stat, read, write }, { nonce }), TypeError)
  t.throws(() => new Keyring({ open, stat, read, write }, { key }), TypeError)

  t.throws(() => new Keyring({
    open, stat, read, write
  }, {
    nonce,
    key: key.slice(0, -1)
  }), TypeError)

  t.throws(() => new Keyring({
    open, stat, read, write
  }, {
    nonce: nonce.slice(0, 23),
    key,
  }), TypeError)

  t.throws(() => new Keyring({
    open, stat, read, write
  }, {
    secret,
    nonce,
    key: key.slice(0, -1)
  }), TypeError)

  t.throws(() => new Keyring({
    open, stat, read, write
  }, {
    secret,
    nonce: nonce.slice(0, 23),
    key,
  }), TypeError)

  t.throws(() => new Keyring({
    open, stat, read, write
  }, {
    secret: empty
  }), TypeError)
})

test('Keyring(storage, opts) instance', (t) => {
  const secret = crypto.randomBytes(64)
  const storage = ram()
  const keyring = new Keyring(storage, { secret })

  // key pairs
  t.true(isBuffer(keyring.publicKey))
  t.true(isBuffer(keyring.secretKey))
  t.true(32 === keyring.publicKey.length)
  t.true(64 === keyring.secretKey.length)

  t.true(storage === keyring.storage)
  t.true(false === keyring.isReady)
  t.true('function' === typeof keyring.lock)

  // accessors
  t.true(isBuffer(keyring.secret))
  t.true(64 === keyring.secret.length)
  t.true(keyring.readable)
  t.true(keyring.writable)
  t.true(keyring.statable)
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
  t.throws(() => keyring.ready(''), TypeError)
  t.throws(() => keyring.ready([ ]), TypeError)
  t.throws(() => keyring.ready({ }), TypeError)
  t.throws(() => keyring.ready(null), TypeError)
  t.throws(() => keyring.ready(true), TypeError)
  t.throws(() => keyring.ready(1234), TypeError)
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
  t.throws(() => keyring.proof(''), TypeError)
  t.throws(() => keyring.proof([ ]), TypeError)
  t.throws(() => keyring.proof({ }), TypeError)
  t.throws(() => keyring.proof(null), TypeError)
  t.throws(() => keyring.proof(true), TypeError)
  t.throws(() => keyring.proof(1234), TypeError)
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

  await t.throws(keyring.append('test', key), TypeError)
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

test('Keyring#createWriteStream(name) throws on bad input', (t) => {
  const secret = crypto.randomBytes(64)
  const keyring = new Keyring(ram(), { secret })
  t.throws(() => keyring.createWriteStream(), TypeError)
  t.throws(() => keyring.createWriteStream(''), TypeError)
  t.throws(() => keyring.createWriteStream(null), TypeError)
  t.throws(() => keyring.createWriteStream(1234), TypeError)
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
