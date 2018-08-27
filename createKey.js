const { warn } = require('ara-console')
const { resolve: pathResolve } = require('path')
const { DID } = require('did-uri')
const crypto = require('ara-crypto')
const debug = require('debug')('ara:network:keyring')
const pify = require('pify')
const keys = require('./keys')
const rc = require('./rc')()
const ss = require('ara-secret-storage')
const fs = require('fs')

async function createKey(opts) {
  let publicKey = null
  let secretKey = null
  let secret = null
  let buffer = null

  try {
    const stat = await pify(fs.stat)(opts.secret)
    if (stat.isFile()) {
      secret = await pify(fs.readFile)(opts.secret)
    }
  } catch (err) {
    void err
  }

  if (opts.identity && 0 !== opts.identity.indexOf('did:ara:')) {
    opts.identity = `did:ara:${opts.identity}`
  }

  const did = new DID(opts.identity)

  secret = Buffer.from(opts.secret)
  const password = crypto.blake2b(Buffer.from(opts.password))
  publicKey = Buffer.from(did.identifier, 'hex')

  // @TODO(jwerle): this should a function of AID
  const hash = crypto.blake2b(publicKey).toString('hex')
  const path = pathResolve(rc.network.identity.root, hash, 'keystore/ara')
  const keystore = JSON.parse(await pify(fs.readFile)(path, 'utf8'))

  try {
    secretKey = ss.decrypt(keystore, { key: password.slice(0, 16) })
  } catch (err) {
    debug(err)
    throw new Error('Invalid passphrase')
  }

  opts.out = pathResolve(opts.out)

  try {
    if (opts.personal) {
      buffer = keys.generate({ secret, publicKey, secretKey })
    } else {
      const keyPair = keys.derive({
        secretKey, name: opts.name
      })

      buffer = keys.generate({
        secret,
        publicKey: keyPair.publicKey,
        secretKey: keyPair.secretKey
      })
    }
  } catch (err) {
    throw err
  }

  try {
    const secretKeyring = keys.keyRing(opts.out, { secret: secretKey })
    const publicKeyring = keys.keyRing(`${opts.out}.pub`, { secret })

    if (opts.personal) {
      if (false === await publicKeyring.has(publicKey)) {
        await publicKeyring.append(publicKey, buffer.slice(0, keys.PK_SIZE))
      } else {
        warn('Public personal keys already exists in public key ring')
      }

      if (false === await secretKeyring.has(secretKey)) {
        await secretKeyring.append(secretKey, buffer.slice(0, keys.PK_SIZE))
      } else {
        warn('Secret personal keys already exists in secret key ring')
      }
    } else {
      if (false === await publicKeyring.has(opts.name)) {
        await publicKeyring.append(opts.name, buffer.slice(0, keys.PK_SIZE))
      } else {
        warn('\'%s\' already exists in public key ring', opts.name)
      }

      if (false === await secretKeyring.has(opts.name)) {
        await secretKeyring.append(opts.name, buffer.slice(keys.PK_SIZE))
      } else {
        warn('\'%s\' already exists in secret key ring', opts.name)
      }
    }
  } catch (err) {
    throw err
  }

  return true
}

module.exports = {
  createKey
}
