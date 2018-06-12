const isBuffer = require('is-buffer')
const crypto = require('ara-crypto')
const debug = require('debug')('ara:network:secret-handshake')

class Handshake {
  constructor(opts) {
    if (opts == null || typeof opts !== 'object') {
      throw new TypeError('Handshake: Expecting object.')
    }

    const {
      remote, client, network, discoveryKey
    } = opts

    this.discoveryKey = discoveryKey
    this.network = network
    this.remote = remote
    this.client = client
    this.crypto = crypto
  }

  /**
   * Create initialization vector (IV)
   *
   * @return {Buffer} 16 bytes of pseudo-random crypto-secure data.
   * Generated by libsodium, see https://download.libsodium.org/doc/generating_random_data/
   */

  iv() {
    return this.crypto.randomBytes(16)
  }

  /**
   * ????
   *
   * @return {Buffer}
   */

  key() {
    return this.discoveryKey.slice(0, 16)
  }

  /**
   * Create digest of handshake transaction
   *
   * @return {Buffer}
   */

  digest() {
    const buffers = []
    buffers.push(this.discoveryKey)
    buffers.push(this.network.publicKey)
    buffers.push(this.remote.publicKey)
    buffers.push(this.client.secretKey)
    return crypto.blake2b(Buffer.concat(buffers))
  }

  /**
   * Create challenge question for remote to ensure we are compatiable
   *
   * @return {Buffer}
   */

  challenge() {
    const iv = this.iv()
    const key = this.key()
    const digest = this.digest()
    const challenge = crypto.encrypt(digest, { key, iv })
    return Buffer.from(JSON.stringify(challenge), 'utf8')
  }

  /**
   * Verify challenge to ensure we are compatiable
   *
   * @param  {Buffer} challenge
   *
   * @return {Boolean}
   */
  proof(challenge) {
    if (isBuffer(challenge)) {
      try { challenge = JSON.parse(challenge.toString('utf8')) } catch (err) {
        debug(err)
        return false
      }
    }

    try {
      const key = this.key()
      const digest = this.digest()
      const proof = crypto.decrypt(challenge, { key })
      if (Buffer.compare(digest, proof) == 0) {
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
