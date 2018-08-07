/* eslint-disable object-curly-newline */
const { Keyring } = require('../keyring')
const crypto = require('ara-crypto')
const test = require('ava')
const ram = require('random-access-memory')

test('Keyring(storage, opts) is a function', (t) => {
  t.true('function' === typeof Keyring)
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
    secret: empty
  }), TypeError)
})

test('Keyring(storage, opts) emits ready for empty instance', async (t) => {
  const secret = crypto.randomBytes(64)
  const keyring = new Keyring(ram, { secret })
  let missing = 3

  t.plan(missing)

  keyring.once('ready', onready)
  await keyring.ready(onready)
  t.true(Boolean(missing--))

  function onready() {
    t.true(Boolean(missing--))
  }
})

test('Keyring(storage, opts) emits ready for existing instance', async (t) => {
  const key = crypto.randomBytes(64)
  const secret = crypto.randomBytes(64)
  const keyring = new Keyring(ram, { secret })
  await keyring.append('test', key)

  const keyringx = new Keyring(ram, { secret })
  let missing = 3

  t.plan(missing)

  keyringx.once('ready', onready)
  await keyringx.ready(onready)
  t.true(Boolean(missing--))

  function onready() {
    t.true(Boolean(missing--))
  }
})

test('Keyring simple', async (t) => {
  const keys = {
    alpha: crypto.ed25519.keyPair(Buffer.alloc(32).fill('alpha')),
    beta: crypto.ed25519.keyPair(Buffer.alloc(32).fill('beta')),
    gamma: crypto.curve25519.keyPair(Buffer.alloc(32).fill('gamma'))
  }

  const secret = Buffer.alloc(64).fill('secret')
  const keyring = new Keyring(ram(), { secret })
  // const keyring = new Keyring('./test-keyring', { secret })

  await new Promise((resolve) => {
    keyring.once('ready', resolve)
  })

  await new Promise((resolve) => {
    keyring.append('alpha', keys.alpha.secretKey, resolve)
  })

  await new Promise((resolve) => {
    keyring.append('beta', keys.beta.secretKey, resolve)
  })

  await new Promise((resolve) => {
    keyring.append('gamma', keys.gamma.secretKey, resolve)
  })

  const key = await new Promise((resolve) => {
    keyring.get('gamma', (err, result) => resolve(result))
  })

  t.true(0 === Buffer.compare(key, keys.gamma.secretKey))
})
