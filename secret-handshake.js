'use strict'

const isBuffer = require('is-buffer')
const secrets = require('./secrets')
const crypto = require('ara-crypto')
const debug = require('debug')('ara:network:secret-handshake')

class Handshake {
  constructor(opts) {
    if (null == opts || 'object' != typeof opts) {
      throw new TypeError("Handshake: Expecting object.")
    }

    const { remote, client, network, discoveryKey } = opts

    this.discoveryKey = discoveryKey
    this.network = network
    this.remote = remote
    this.client = client
  }

  iv() {
    return crypto.randomBytes(16)
  }

  key() {
    return this.discoveryKey.slice(0, 16)
  }

  digest() {
    const buffers = []
    buffers.push(this.discoveryKey)
    buffers.push(this.network.publicKey)
    buffers.push(this.remote.publicKey)
    buffers.push(this.client.secretKey)
    return crypto.blake2b(Buffer.concat(buffers))
  }

  challenge() {
    const iv = this.iv()
    const key = this.key()
    const digest = this.digest()
    const challenge = crypto.encrypt(digest, {key, iv})
    return Buffer.from(JSON.stringify(challenge), 'utf8')
  }

  proof(challenge) {
    if (isBuffer(challenge)) {
      try { challenge = JSON.parse(challenge.toString('utf8')) }
      catch (err) {
        debug(err)
        return false
      }
    }

    try {
      const key = this.key()
      const digest = this.digest()
      const proof = crypto.decrypt(challenge, {key})
      if (0 == Buffer.compare(digest, proof)) {
        return true
      }
    } catch (err) {
      debug(err)
    }

    return false
  }
}

module.exports = {
  Handshake
}
