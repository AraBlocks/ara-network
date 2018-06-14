const { test } = require('ava')
const crypto = require('ara-crypto')
const sinon = require('sinon')
const fs = require('fs')
const {
  encrypt,
  decrypt,
  derive,
  load,
} = require('../secrets')

const HEXCONST = 0xDEADBEEF

test('encrypt - throws error on no opts', (t) => {
  t.throws(() => { encrypt() }, TypeError)
})

test('encrypt - throws error on no Buffer or string', (t) => {
  t.throws(() => { encrypt({ key: 1 }) }, TypeError)
  t.notThrows(() => { encrypt({ key: 'a' }) }, TypeError)
  t.notThrows(() => { encrypt({ key: Buffer.from('a') }) }, TypeError)
})

test('encrypt - throws error if remote keypair is too long', (t) => {
  // Makes a key that is too only contain private and public
  t.throws(() => { encrypt({ key: 'a', remote: Buffer.alloc(128, HEXCONST) }) }, TypeError)
})

test('encrypt - throws error if client keypair is too long', (t) => {
  // Makes a key that is too only contain private and public
  t.throws(() => { encrypt({ key: 'a', client: Buffer.alloc(128, HEXCONST) }) }, TypeError)
})

test('encrypt - throws error if remote keypair doesn\'t contain a secret key', (t) => {
  // Makes a key that should only contain public
  t.throws(() => { encrypt({ key: 'a', remote: Buffer.alloc(32, HEXCONST) }) }, TypeError)
})

test('encrypt - throws error if client keypair doesn\'t contain a secret key', (t) => {
  // Makes a key that should only contain public
  t.throws(() => { encrypt({ key: 'a', client: Buffer.alloc(32, HEXCONST) }) }, TypeError)
})

test('encrypt - throws error if remote keypair doesn\'t contain a secret key', (t) => {
  const pack = encrypt({ key: 'a' })

  // Ensures things that should be there are there
  t.truthy(pack.public)
  t.truthy(pack.secret)
  t.truthy(pack.public.keystore)
  t.truthy(pack.secret.keystore)
})

test('decrypt - converts to buffer', (t) => {
  sinon.stub(crypto, 'blake2b').callsFake((key, size) => {
    // Makes sure that the key is correctly cast to a buffer somewhere
    t.true(key instanceof Buffer)

    return Buffer.alloc(size || 32)
  })

  const pack = encrypt({ key: 'a' })
  decrypt(pack.public, { key: 'a' })
})

test('decrypt - decrypts public', (t) => {
  const pack = encrypt({ key: 'a' })
  const decrypted = decrypt(pack.public, { key: 'a' })

  /*
   * Checks for the things that should and shouldn't be there,
   *  according to what is being set in the function
   */
  t.truthy(!decrypted.network.secretKey)
  t.truthy(!decrypted.remote.secretKey)
  t.truthy(decrypted.client.secretKey)
  t.truthy(decrypted.client.publicKey)
})

test('decrypt - decrypts secret', (t) => {
  const pack = encrypt({ key: 'a' })
  const decrypted = decrypt(pack.secret, { key: 'a' })

  /*
   * Checks for the things that should and shouldn't be there,
   *  according to what is being set in the function
   */
  t.truthy(decrypted.network.secretKey)
  t.truthy(decrypted.remote.secretKey)
  t.truthy(decrypted.client.secretKey)

  t.truthy(decrypted.network.publicKey)
  t.truthy(decrypted.remote.publicKey)
  t.truthy(decrypted.client.publicKey)
})

test('derive - returns doc if remote secret defined', (t) => {
  const pack = encrypt({ key: 'a' })

  const { secret } = derive(pack.secret, { key: 'a' })

  t.is(secret, pack.secret)
})

test('derive - returns doc if remote secret not defined', (t) => {
  const pack = encrypt({ key: 'a' })

  const derived = derive(pack.public, { key: 'a' })

  t.is(derived.public, pack.public)
})

test('load - throws error on no opts', async (t) => {
  try {
    await load()
    t.fail()
  } catch (e) {
    t.pass()
  }
})

test('load - throws error on opts.key not being a buffer or string', async (t) => {
  try {
    await load({ key: 1 })
    t.fail()
  } catch (e) {
    t.pass()
  }
})

test('load - loads public', async (t) => {
  sinon.stub(fs, 'access').callsFake((name, cb) => cb(null, true))

  sinon.stub(fs, 'readFile').callsFake((name, opts, cb) => cb(null, { a: 1 }))

  try {
    const result = await load({ key: 'a', public: true })
    t.truthy(result)
    t.true(result.public.a == 1)
    t.pass()
  } catch (e) {
    t.fail()
  }
})

test('load - loads private', async (t) => {
  sinon.stub(fs, 'access').callsFake((name, cb) => cb(null, true))

  sinon.stub(fs, 'readFile').callsFake((name, opts, cb) => cb(null, { a: 1 }))

  try {
    const result = await load({ key: 'a', public: false })
    t.truthy(result)
    t.true(result.private.a == 1)
    t.pass()
  } catch (e) {
    t.fail()
  }
})
