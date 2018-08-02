const { Keyring } = require('../keyring')
const crypto = require('ara-crypto')
const test = require('ava')
const ram = require('random-access-memory')

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
