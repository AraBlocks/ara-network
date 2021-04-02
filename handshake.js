const { Duplex } = require('readable-stream')
const isBuffer = require('is-buffer')
const through = require('through2')
const crypto = require('ara-crypto')
const pump = require('pump')

const $session = Symbol('session')
const $version = Symbol('version')
const $domain = Symbol('domain')
const $remote = Symbol('remote')
const $local = Symbol('local')
const $nonce = Symbol('nonce')
const $phase = Symbol('phase')

/**
 * The Handshake protocol version string.
 * @private
 */
const kVersion = 'ARANET1'

/**
 * A class that represents an implementation of a slightly modified
 * version of Dominic Tarr's Secret Handshake.
 * @public
 * @class Handshake
 * @extends stream.Duplex
 * @see {@link http://dominictarr.github.io/secret-handshake-paper/shs.pdf}
 */
class Handshake extends Duplex {
  /**
   * Static accessor to get the version of this handshake.
   * @public
   * @static
   * @accessor
   * @type {Buffer}
   */
  static get VERSION() { return kVersion }

  /**
   * Handshake class constructor.
   * @public
   * @constructor
   * @param {Object} opts
   * @throws TypeError
   * @see {@link State}
   */
  constructor(opts) {
    super()

    if (!opts || 'object' !== typeof opts) {
      throw new TypeError('Handshake: Expecting object.')
    }

    this.setMaxListeners(0)

    this.source = through()
    this.state = new State(clone(opts, {
      version: opts.version || kVersion,
      nonce: Buffer.alloc(32).fill(opts.version || kVersion)
    }))
  }

  toString() {
    return this.isAlice
      ? `Handshake<Alice ${this.state.publicKey.toString('hex')}>`
      : `Handshake<Bob ${this.state.publicKey.toString('hex')}>`
  }

  _read() {
    void this
  }

  _write(chunk, enc, done) {
    if ('function' === typeof enc) {
      done = enc
    }

    if (State.OKAY === this.state.phase) {
      this.source.push(chunk)
    } else {
      try {
        this.onmessage(chunk)
      } catch (err) {
        this.emit('error', err)
      }
    }

    done(null)
  }

  /**
   * Handles raw messages written to the duplex stream.
   * @private
   */
  onmessage(chunk) {
    const { phase } = this.state

    if (State.HELLO === phase) {
      this.onhello(chunk)
    }

    if (State.AUTH === phase) {
      this.onauth(chunk)
    }
  }

  /**
   * Handle incoming HELLO from remote party
   * A <- ? : bp, HMAC[k](bp)
   * @private
   */
  onhello(chunk) {
    const { state } = this
    const { domain } = state
    const { session } = state

    const hello = {
      mac: chunk.slice(0, 32),
      publicKey: chunk.slice(32)
    }

    let key = null

    if (isBuffer(session.remote.publicKey)) {
      return
    }

    if (isBob(this)) {
      key = crypto.blake2b(domain.publicKey)
    } else if (isAlice(this)) {
      key = crypto.curve25519.shared(
        domain.publicKey,
        crypto.curve25519.shared(session.local.publicKey, hello.publicKey),
      )
    } else {
      throw handshakeStateError()
    }

    if (crypto.auth.verify(hello.mac, hello.publicKey, key)) {
      this.state.session.remote.publicKey = hello.publicKey
      this.state.session.remote.nonce = hello.mac.slice(0, 24)

      this.state[$phase] = State.AUTH
      this.emit('hello', hello)
    } else {
      this.state[$phase] = State.NONE
      throw handshakeVerificationError()
    }
  }

  onauth(chunk) {
    const { state } = this
    const { nonce } = state
    const { local } = state
    const { remote } = state
    const { domain } = state
    const { session } = state

    if (isBob(this)) {
      const key = Buffer.concat([
        domain.publicKey,

        crypto.curve25519.shared(
          session.remote.publicKey,
          session.local.publicKey

        ),
        crypto.curve25519.shared(
          session.remote.publicKey,
          local.publicKey
        ),
      ])

      const unboxed = crypto.unbox(chunk, { key, nonce })
      const publicKey = unboxed.slice(0, 32)
      const signature = unboxed.slice(32)

      if (!this.verify(publicKey, signature)) {
        throw handshakeAuthenticationError()
      }

      this.emit('auth', { publicKey, signature })

      if (!this.okay(unboxed)) {
        throw handshakeAuthenticationError()
      }

      this.state[$phase] = State.OKAY
      this.emit('okay', signature)
    } else if (isAlice(this)) {
      const key = Buffer.concat([
        domain.publicKey,

        crypto.curve25519.shared(
          session.local.publicKey,
          session.remote.publicKey
        ),

        crypto.curve25519.shared(
          session.local.publicKey,
          remote.publicKey
        ),

        crypto.curve25519.shared(
          local.publicKey,
          session.remote.publicKey
        )
      ])

      const signature = crypto.unbox(chunk, { key, nonce })

      if (!this.verify(remote.publicKey, signature)) {
        throw handshakeAuthenticationError()
      }

      this.emit('auth', { publicKey: remote.publicKey, signature })

      if (!this.okay(signature)) {
        throw handshakeAuthenticationError()
      }

      this.state[$phase] = State.OKAY
      this.emit('okay', signature)
    } else {
      throw handshakeStateError()
    }
  }

  /**
   * Accessor to determine if handshake is in "alice" state.
   * @public
   * @accessor
   * @type {Boolean}
   */
  get isAlice() {
    return isAlice(this)
  }

  /**
   * Accessor to determine if handshake is in "bob" state.
   * @public
   * @accessor
   * @type {Boolean}
   */
  get isBob() {
    return isBob(this)
  }

  /**
   * Sends HELLO to remote party in handshake containing a public session
   * key and a MAC of it signed by a shared domain key.
   * ? -> ? : ap, HMAC[k](ap)
   * @public
   * @return {Boolean}
   */
  hello() {
    const { state } = this
    const { domain } = state
    const { session } = state

    let key = null

    if (isBob(this)) {
      key = crypto.curve25519.shared(
        domain.publicKey,
        crypto.curve25519.shared(
          session.remote.publicKey,
          session.local.publicKey
        )
      )
    } else if (isAlice(this)) {
      key = crypto.blake2b(domain.publicKey)
    } else {
      throw handshakeStateError()
    }

    const mac = crypto.auth(session.local.publicKey, key)
    const buffer = Buffer.concat([ mac, session.local.publicKey ])

    state.session.local.nonce = mac.slice(0, 24)

    return this.push(buffer)
  }

  /**
   * Computes and sends a client authentication message AUTH with
   * alice's public key and a signature produced by her secret key.
   * A -> B : Ap|sign[A](K|B[p]|hash(a . b)
   * @public
   * @return {Boolean}
   * @throws TypeError
   */
  auth() {
    const { state } = this
    const { nonce } = state
    const { local } = state
    const { remote } = state
    const { domain } = state
    const { session } = state

    if (isBob(this)) {
      throw new TypeError('Client state required to send authentication.')
    }

    const H = Buffer.concat([
      local.publicKey,

      crypto.ed25519.sign(
        Buffer.concat([
          domain.publicKey,
          remote.publicKey,
          crypto.blake2b(crypto.curve25519.shared(
            session.local.publicKey,
            session.remote.publicKey
          ))
        ]),

        local.secretKey
      )
    ])

    const key = Buffer.concat([
      domain.publicKey,

      crypto.curve25519.shared(
        session.local.publicKey,
        session.remote.publicKey
      ),

      crypto.curve25519.shared(
        session.local.publicKey,
        remote.publicKey
      ),
    ])

    const box = crypto.box(H, { key, nonce })

    return this.push(box)
  }

  /**
   * Verifies a public key and signature against a computed
   * proof for either "alice" or "bob" states.
   * @public
   * @param {Buffer} publicKey
   * @param {Buffer} signature
   * @return Boolean
   * @throws TypeError
   * @emits auth
   */
  verify(publicKey, signature) {
    const { state } = this
    const { local } = state
    const { domain } = state
    const { session } = state

    if (!publicKey || false === isBuffer(publicKey)) {
      throw new TypeError('Expecting public key to be a buffer.')
    }

    if (!signature || false === isBuffer(signature)) {
      throw new TypeError('Expecting signature to be a buffer.')
    }

    let verified = false

    if (isBob(this)) {
      const proof = Buffer.concat([
        domain.publicKey,
        local.publicKey,
        crypto.blake2b(crypto.curve25519.shared(
          session.remote.publicKey,
          session.local.publicKey
        ))
      ])

      verified = crypto.ed25519.verify(signature, proof, publicKey)
    } else if (isAlice(this)) {
      const H = Buffer.concat([
        local.publicKey,

        crypto.ed25519.sign(
          Buffer.concat([
            domain.publicKey,
            publicKey,
            crypto.blake2b(crypto.curve25519.shared(
              session.local.publicKey,
              session.remote.publicKey
            ))
          ]),

          local.secretKey
        )
      ])

      const proof = Buffer.concat([
        domain.publicKey,
        H,
        crypto.blake2b(crypto.curve25519.shared(
          session.local.publicKey,
          session.remote.publicKey,
        ))
      ])

      verified = crypto.ed25519.verify(signature, proof, publicKey)
    }

    return verified
  }

  /**
   * Sends OKAY reply for some chunk if handshake is considered to
   * be "bob", otherwise checks for correct "alice" state and upgrades
   * state to OKAY
   * @public
   * @param {Buffer} chunk
   * @return Boolean
   * @emits okay
   */
  okay(chunk) {
    const { state } = this
    const { nonce } = state
    const { phase } = state
    const { local } = state
    const { remote } = state
    const { domain } = state
    const { session } = state

    if (State.AUTH === phase && isAlice(this)) {
      if (
        isBuffer(session.remote.publicKey)
        && isBuffer(session.remote.nonce)
      ) {
        return true
      }
    }

    if (State.AUTH === phase && isBob(this)) {
      const alice = {
        publicKey: chunk.slice(0, 32),
        signature: chunk.slice(32)
      }

      const key = Buffer.concat([
        domain.publicKey,

        crypto.curve25519.shared(
          session.remote.publicKey,
          session.local.publicKey
        ),

        crypto.curve25519.shared(
          session.remote.publicKey,
          local.publicKey
        ),

        crypto.curve25519.shared(
          alice.publicKey,
          session.local.publicKey,
        )
      ])

      const proof = Buffer.concat([
        domain.publicKey,
        chunk,
        crypto.blake2b(crypto.curve25519.shared(
          session.remote.publicKey,
          session.local.publicKey
        ))
      ])

      const signature = crypto.ed25519.sign(proof, local.secretKey)
      const boxed = crypto.box(signature, { key, nonce })

      remote.publicKey = alice.publicKey

      if (this.push(boxed)) {
        return true
      }
    }

    return false
  }

  /**
   * Creates a writable stream that emits ciphertext
   * from plaintext written to this handshake stream based
   * on shared session keys between two parties.
   * @public
   * @return {Duplex}
   * @throws TypeError
   */
  createWriteStream() {
    const { state } = this
    const { phase } = state
    const { local } = state
    const { domain } = state
    const { remote } = state
    const { session } = state

    if (State.OKAY !== phase) {
      throw handshakeStatePhaseError()
    }

    let nonce = null
    let key = null

    if (isBob(this)) {
      nonce = Buffer.concat([ session.remote.nonce, session.local.nonce ])
      key = Buffer.concat([
        domain.publicKey,

        crypto.curve25519.shared(
          session.remote.publicKey,
          session.local.publicKey
        ),

        crypto.curve25519.shared(
          session.remote.publicKey,
          local.publicKey
        ),

        crypto.curve25519.shared(
          remote.publicKey,
          session.local.publicKey
        ),
      ])
    } else if (isAlice(this)) {
      nonce = Buffer.concat([ session.local.nonce, session.remote.nonce ])
      key = Buffer.concat([
        domain.publicKey,

        crypto.curve25519.shared(
          session.local.publicKey,
          session.remote.publicKey
        ),

        crypto.curve25519.shared(
          session.local.publicKey,
          remote.publicKey
        ),

        crypto.curve25519.shared(
          local.publicKey,
          session.remote.publicKey
        )
      ])
    } else {
      throw handshakeStateError()
    }

    const stream = crypto.createBoxStream({ key, nonce })
    const push = this.push.bind(this)

    this.once('destroy', ondestroy)

    stream.on('data', ondata)
    stream.on('error', (err) => {
      cleanup()
      this.emit('error', err)
    })

    return stream

    function cleanup() {
      stream.removeListener('data', ondata)
    }

    function ondata(chunk) {
      push(chunk)
    }

    function ondestroy(err) {
      cleanup()
      stream.destroy(err)
    }
  }

  /**
   * Creates a readable stream that emits plaintext
   * from ciphertext written to this handshake stream based
   * on shared session keys between two parties.
   * @public
   * @return {Duplex}
   * @throws TypeError
   */
  createReadStream() {
    const { state } = this
    const { phase } = state
    const { local } = state
    const { domain } = state
    const { remote } = state
    const { session } = state

    if (State.OKAY !== phase) {
      throw handshakeStatePhaseError()
    }

    let nonce = null
    let key = null

    if (isBob(this)) {
      nonce = Buffer.concat([ session.remote.nonce, session.local.nonce ])
      key = Buffer.concat([
        domain.publicKey,

        crypto.curve25519.shared(
          session.remote.publicKey,
          session.local.publicKey
        ),

        crypto.curve25519.shared(
          session.remote.publicKey,
          local.publicKey
        ),

        crypto.curve25519.shared(
          remote.publicKey,
          session.local.publicKey
        ),
      ])
    } else if (isAlice(this)) {
      nonce = Buffer.concat([ session.local.nonce, session.remote.nonce ])
      key = Buffer.concat([
        domain.publicKey,

        crypto.curve25519.shared(
          session.local.publicKey,
          session.remote.publicKey
        ),

        crypto.curve25519.shared(
          session.local.publicKey,
          remote.publicKey
        ),

        crypto.curve25519.shared(
          local.publicKey,
          session.remote.publicKey
        )
      ])
    } else {
      throw handshakeStateError()
    }

    const stream = crypto.createUnboxStream({ key, nonce })

    pump(this.source, stream)

    return stream
  }
}

/**
 * Handshake cryptography and protocol state.
 *
 * @public
 * @class State
 */
class State {
  /**
   * Reserved handshake states 0x00...0x1F
   */
  static get NONE() { return 0x00 }

  static get HELLO() { return 0x01 }

  static get AUTH() { return 0x02 }

  static get OKAY() { return 0x1E }

  /**
   * State class constructor.
   *
   * @public
   * @constructor
   * @param {Object} opts
   * @param {Buffer} opts.secret
   * @param {Buffer} opts.publicKey
   * @param {Buffer} opts.secretKey
   * @param {Object} opts.domain
   * @param {Buffer} opts.domain.publicKey
   * @param {Buffer} opts.domain.secretKey
   * @param {Object} opts.remote
   * @param {Buffer} opts.remote.publicKey
   * @param {Buffer} opts.remote.secretKey
   * @throws TypeError
   */
  constructor(opts) {
    if (!opts || 'object' !== typeof opts) {
      throw new TypeError('State: Expecting object')
    }

    // use a zero buffer as default nonce
    const { nonce = Buffer.alloc(32).fill(0) } = opts
    const { publicKey, secretKey } = opts
    const { remote = {}, domain } = opts
    const { secret, version } = opts

    // derive curve25519 key pair from secret key and secret
    // K = BLAKE2b(BLAKE2b(s) . BLAKE2b(Bs))
    if (false === isBuffer(domain.publicKey) && secret && isBuffer(secretKey)) {
      const s = crypto.blake2b(secret, 32)
      const bs = crypto.blake2b(secretKey, 32)
      const seed = crypto.blake2b(Buffer.concat([ s, bs ]), 32)
      Object.assign(domain, crypto.curve25519.keyPair(seed))
    }

    const session = {
      local: crypto.curve25519.keyPair(),
      remote: { publicKey: null, secretKey: null },
    }

    // session state (K)
    this[$session] = {
      get local() { return session.local },
      get remote() { return session.remote },
    }

    // domain state (K)
    this[$domain] = {
      get publicKey() { return domain.publicKey || null },
      get secretKey() { return domain.secretKey || null },
    }

    // remote state (A or B)
    this[$remote] = {
      set publicKey(key) { remote.publicKey = key || null },
      get publicKey() { return remote.publicKey || null },
      get secretKey() { return null },
    }

    // local state (A or B)
    this[$local] = {
      get publicKey() { return publicKey },
      get secretKey() { return secretKey },
    }

    // handshake nonce
    this[$nonce] = nonce

    // handshake state phase
    this[$phase] = State.HELLO

    // handshake version
    this[$version] = version
  }

  get publicKey() { return this[$local].publicKey }

  get secretKey() { return this[$local].secretKey }

  get version() { return this[$version] }

  get session() { return this[$session] }

  get domain() { return this[$domain] }

  get remote() { return this[$remote] }

  get local() { return this[$local] }

  get nonce() { return this[$nonce] }

  get phase() { return this[$phase] }
}

function clone(object, extended) {
  return { ...object, ...extended }
}

function isBob(shake) {
  return Boolean(shake && shake.state && shake.state.domain.secretKey)
}

function isAlice(shake) {
  return Boolean(!isBob(shake)
    && shake
    && shake.state
    && shake.state.domain.publicKey)
}

function handshakeStateError() {
  return new TypeError('Unknown handshake state')
}

function handshakeStatePhaseError() {
  return new TypeError('Bad handshake state phase.')
}

function handshakeVerificationError() {
  return new Error('Handshake failed to verify hello.')
}

function handshakeAuthenticationError() {
  return new Error('Handshake failed in authentication.')
}

module.exports = {
  Handshake,
  State,
}
