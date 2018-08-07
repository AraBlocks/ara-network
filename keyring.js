const { EventEmitter } = require('events')
const isBuffer = require('is-buffer')
const collect = require('collect-stream')
const merkle = require('merkle-tree-stream/generator')
const crypto = require('ara-crypto')
const mutex = require('mutexify')
const split = require('split-buffer')
const raf = require('random-access-file')

// 34 = 2 + (2 * crypto_secretbox_MACBYTES)
const kBoxHeaderSize = 34
const kSignatureSize = 64
const kHeaderSize = 8 + 8

/**
 * The Keyring class implements a secure append only list of named keys.
 * @public
 * @class Keyring
 * @extends EventEmitter
 */
class Keyring extends EventEmitter {
  /**
   * Keyring class constructor.
   * @constructor
   * @param {String|Function|RandomAccessStorage} storage
   * @param {Object} opts
   * @param {?(Buffer)} opts.key
   * @param {?(Buffer)} opts.nonce
   * @param {?(Buffer)} opts.secret
   * @param {?(Boolean)} [opts.readonly = false]
   * @throws TypeError
   */
  constructor(storage, opts) {
    super()

    if (null === storage) {
      throw new TypeError('Keyring: Storage cannot be null.')
    } else if (undefined === storage) {
      throw new TypeError('Keyring: Storage cannot be undefined.')
    } else if ('object' !== typeof storage) {
      if ('string' === typeof storage) {
        if (0 === storage.length) {
          throw new TypeError('Keyring: Storage path cannot be empty.')
        } else {
          // eslint-disable-next-line no-param-reassign
          storage = raf(storage)
        }
      } else if ('function' === typeof storage) {
        // eslint-disable-next-line no-param-reassign
        storage = storage(this, opts)
        if (!storage || 'object' !== typeof storage) {
          throw new TypeError('Keyring: Storage must resolve to an object.')
        }
      } else {
        // eslint-disable-next-line function-paren-newline
        throw TypeError(
          'Keyring: Expecting storage to be an object, string, or function.')
      }
    }

    if ('function' !== typeof storage.open) {
      throw new TypeError('Keyring: Expecting storage.open() to be a function.')
    }

    if ('function' !== typeof storage.stat) {
      throw new TypeError('Keyring: Expecting storage.stat() to be a function.')
    }

    if ('function' !== typeof storage.read) {
      throw new TypeError('Keyring: Expecting storage.read() to be a function.')
    }

    if ('function' !== typeof storage.write) {
      // eslint-disable-next-line function-paren-newline
      throw new TypeError(
        'Keyring: Expecting storage.write() to be a function.')
    }

    if (!opts || 'object' !== typeof opts) {
      throw new TypeError('Keyring: Expecting options to be an object.')
    }

    this.setMaxListeners(0)

    if (isBuffer(opts.secret)) {
      if (opts.secret.length < 64) {
        throw new TypeError('Keyring: Secret must be at least 64 bytes.')
      } else {
        this.key = opts.secret.slice(0, 32)
        this.nonce = opts.secret.slice(32)
      }
    }

    if (isBuffer(opts.nonce)) {
      if (opts.nonce.length < 24) {
        throw new TypeError('Keyring: Nonce must be at least 24 bytes.')
      } else {
        this.nonce = Buffer.alloc(32)
        opts.nonce.copy(this.nonce)
      }
    }

    if (isBuffer(opts.key)) {
      if (32 !== opts.key.length) {
        throw new TypeError('Keyring: Expecting key to be 32 bytes.')
      } else {
        this.key = opts.key
      }
    }

    if (false === isBuffer(this.nonce)) {
      throw new TypeError('Keyring: Expecting nonce to be a buffer.')
    }

    if (false === isBuffer(this.key)) {
      throw new TypeError('Keyring: Expecting key to be a buffer.')
    }

    const keyring = this
    const seed = crypto.blake2b(this.secret)

    const { publicKey, secretKey } = crypto.ed25519.keyPair(seed)

    this.publicKey = publicKey
    this.secretKey = secretKey
    this.storage = storage
    this.isReady = false
    this.lock = mutex()

    if (true === opts.readonly) {
      this.storage.preferReadonly = true
    } else {
      this.storage.preferReadonly = false
    }

    this.storage.open(onopen)
    this.once('ready', () => {
      this.isReady = true
    })

    function onopen(err) {
      if (err) {
        keyring.emit('error', err)
      } else {
        keyring.proof(onproof)
      }
    }

    function onproof(err, proof) {
      if (err) {
        keyring.emit('error', err)
      } else {
        computeRoots(keyring, onroots)
      }

      // eslint-disable-next-line no-shadow
      function onroots(err, roots) {
        if (err) {
          keyring.emit('error', err)
        } else if (proof && roots && proof.length && roots.length) {
          if (crypto.ed25519.verify(proof, roots, publicKey)) {
            keyring.emit('ready')
          } else {
            keyring.emit('error', new Error('Keyring: Integrity check failed.'))
          }
        } else {
          keyring.emit('ready')
        }
      }
    }
  }

  /**
   * Returns a buffer representation of the secret associated with
   * this Keyring.
   * @public
   * @accessor
   * @type {Buffer}
   */
  get secret() {
    return Buffer.concat([
      this.key.slice(0, 32),
      this.nonce.slice(0, 32)
    ])
  }

  /**
   * Will be true if the keyring storage is writable.
   * @public
   * @accessor
   * @type {Boolean}
   */
  get writable() {
    return this.storage.writable
  }

  /**
   * Will be true if the keyring storage is readable.
   * @public
   * @accessor
   * @type {Boolean}
   */
  get readable() {
    return this.storage.readable
  }

  /**
   * Will be true if the keyring storage is statable.
   * @public
   * @accessor
   * @type {Boolean}
   */
  get statable() {
    return this.storage.statable
  }

  /**
   * Computes the short hash (SipHash) of a keyring entry name.
   * @public
   * @param {?(String)} name
   * @return {Buffer}
   */
  hash(name) {
    const buf = Buffer.from(name || [ 0x0 ])
    return crypto.shash(buf, this.secretKey.slice(0, 16))
  }

  /**
   * Call a function when keyring is in a ready state.
   * @public
   * @param {?(Function)} cb
   * @return {Promise}
   */
  ready(cb) {
    const { isReady } = this
    // eslint-disable-next-line no-param-reassign
    cb = ensureCallback(cb)
    return new Promise((resolve) => {
      if (isReady) {
        process.nextTick(onready)
      } else {
        this.once('ready', onready)
      }

      function onready() {
        cb()
        resolve()
      }
    })
  }

  /**
   * Reads the 64 byte keyring signature, if computed.
   * @public
   * @param {?(Function)} cb
   * @return {Promise<Buffer>}
   */
  proof(cb) {
    const { storage } = this
    // eslint-disable-next-line no-param-reassign
    cb = ensureCallback(cb)

    return new Promise((resolve, reject) => {
      this.stat(onstat)

      function onstat(err, stat) {
        if (err) {
          cb(err)
          reject(err)
        } else if (stat.size >= kSignatureSize) {
          storage.read(0, kSignatureSize, onproof)
        } else {
          cb(null, null)
          resolve(null)
        }
      }

      function onproof(err, proof) {
        cb(err, proof)
        if (err) {
          reject(err)
        } else {
          resolve(proof)
        }
      }
    })
  }

  /**
   * Get the size of the keyring storage.
   * @public
   * @param {Function} cb
   */
  stat(cb) {
    const { storage } = this
    // eslint-disable-next-line no-param-reassign
    cb = ensureCallback(cb)
    return new Promise((resolve, reject) => {
      if ('number' === typeof storage.length) {
        process.nextTick(onstat, null, { size: storage.length })
      } else if (storage.statable) {
        storage.stat(onstat)
      } else {
        process.nextTick(onstat, null, { size: 0 })
      }

      function onstat(err, stat) {
        cb(err, stat)
        if (err) {
          reject(err)
        } else {
          resolve(stat)
        }
      }
    })
  }

  /**
   * Appends a key to the keyring by name. This function
   * will compute Merkle root nodes and rewrite the keyring
   * signature.
   * @public
   * @param {String} name
   * @param {Buffer} key
   * @param {?(Function)} cb
   * @return {Promise<Object>}
   * @emits append
   * @throws TypeError
   */
  append(name, key, cb) {
    if (!name || 'string' !== typeof name) {
      throw new TypeError('Keyring: Expecting name to be a string.')
    }

    if (false === isBuffer(key)) {
      throw new TypeError('Keyring: Expecting key to be a buffer.')
    }

    // eslint-disable-next-line no-param-reassign
    cb = ensureCallback(cb)
    return new Promise((resolve, reject) => {
      const stream = this.createWriteStream(name)
      const parts = split(key, 4 * 1024)

      stream.once('error', onerror)
      stream.once('put', onput)
      stream.once('put', () => {
        this.emit('append', name)
      })

      for (const part of parts) {
        stream.write(part)
      }

      stream.end()

      function onerror(err) {
        reject(err)
      }

      // eslint-disable-next-line no-shadow
      function onput(name, hash) {
        cb(null, { name, hash })
        resolve({ name, hash })
      }
    })
  }

  /**
   * Gets a keyring by name.
   * @public
   * @param {String} name
   * @param {?(Function)} cb
   * @return {Promise<Buffer>}
   * @throws TypeError
   */
  get(name, cb) {
    if (!name || 'string' !== typeof name) {
      throw new TypeError('Keyring: Expecting name to be a string.')
    }

    // eslint-disable-next-line no-param-reassign
    cb = ensureCallback(cb)
    return new Promise((resolve, reject) => {
      const stream = this.createReadStream(name)
      collect(stream, oncollect)

      function oncollect(err, result) {
        cb(err, result)

        if (err) {
          reject(err)
        } else {
          resolve(result)
        }
      }
    })
  }

  /**
   * Determine if named key has access in underlying storage.
   * @public
   * @param {String} name
   * @param {?(Function)} cb
   * @return {Promise}
   * @throws TypeError
   */
  access(name, cb) {
    if (!name || 'string' !== typeof name) {
      throw new TypeError('Keyring: Expecting name to be a string.')
    }

    // eslint-disable-next-line no-param-reassign
    cb = ensureCallback(cb)
    return new Promise((resolve, reject) => {
      this.get(name, onget)

      function onget(err, entry) {
        if (err) {
          cb(err)
          reject(err)
        } else if (!entry || 0 === entry.length) {
          const error = new Error(`Keyring: No such entry exists: '${name}'`)
          cb(error)
          reject(error)
        } else {
          cb(null)
          resolve()
        }
      }
    })
  }

  /**
   * Determine if keyring has a named key.
   * @public
   * @param {String} name
   * @param {?(Function)} cb
   * @return {Promise<Boolean>}
   * @throws TypeError
   */
  has(name, cb) {
    if (!name || 'string' !== typeof name) {
      throw new TypeError('Keyring: Expecting name to be a string.')
    }

    // eslint-disable-next-line no-param-reassign
    cb = ensureCallback(cb)
    return new Promise((resolve) => {
      this.access(name, onaccess)
      function onaccess(err) {
        cb(null, null === err)
        resolve(null === err)
      }
    })
  }

  /**
   * Computes the Merkle tree roots for this keyring
   * at the current state of the storage.
   * @public
   * @param {?(Function)} cb
   * @return {Promise<Buffer>}
   */
  computeRoots(cb) {
    // eslint-disable-next-line no-param-reassign
    cb = ensureCallback(cb)
    return new Promise((resolve, reject) => {
      computeRoots(this, onroots)

      function onroots(err, roots) {
        cb(err, roots)
        if (err) {
          reject(err)
        } else {
          resolve(roots)
        }
      }
    })
  }

  /**
   * Computes and writes an ed25519 signature using a keyring's secret key
   * and the computed Merkle roots for a key ring. The signature is stored in
   * the keyring's storage at offset 0 and is 64 bytes wide.
   * @public
   * @param {?(Function)} cb
   * @return {Promise<Buffer>}
   */
  computeSignature(cb) {
    // eslint-disable-next-line no-param-reassign
    cb = ensureCallback(cb)
    return new Promise((resolve, reject) => {
      computeSignature(this, onsignature)

      function onsignature(err, signature) {
        cb(err, signature)
        if (err) {
          reject(err)
        } else {
          resolve(signature)
        }
      }
    })
  }

  /**
   * Creates a read stream that unboxes an encrypted key found in
   * the underlying storage by name and provides it as a stream.
   * @public
   * @param {String} name
   * @throws TypeError
   */
  createReadStream(name) {
    if (!name || 'string' !== typeof name) {
      throw new TypeError('Keyring: Expecting name to be a string.')
    }

    if (false === this.readable) {
      throw new TypeError('Keyring: Not readable.')
    }

    const { storage } = this
    const keyring = this
    const nonce = this.nonce.slice(0, 24)
    const hash = this.hash(name)
    const key = this.key.slice(0, 32)

    const stream = crypto.createUnboxStream({ nonce, key })

    let off = kSignatureSize

    // read first entry header after signature
    process.nextTick(seek, kHeaderSize)

    return stream

    function seek(size, next) {
      keyring.stat(onstat)

      function onstat(err, stat) {
        if (off + size <= stat.size) {
          storage.read(off, size, next || onread)
          off += size
        } else {
          stream.end()
        }
      }
    }

    function onread(err, buf) {
      if (err) {
        stream.emit('error', err)
      } else {
        const header = {
          length: crypto.uint64.decode(buf.slice(0, 8)),
          hash: buf.slice(8)
        }

        // eslint-disable-next-line no-shadow
        seek(header.length, (err, entry) => {
          if (err) {
            stream.emit('error', err)
          } else if (0 === Buffer.compare(hash, header.hash)) {
            const head = entry.slice(0, kBoxHeaderSize)
            const body = entry.slice(kBoxHeaderSize)
            stream.write(head)
            stream.end(body)
          } else {
            seek(kHeaderSize)
          }
        })
      }
    }
  }

  /**
   * Creates a write stream that boxes input into an encrypted key
   * that is stored in the underlying keyring storage by name.
   * @public
   * @param {String} name
   * @throws TypeError
   */
  createWriteStream(name) {
    if (!name || 'string' !== typeof name) {
      throw new TypeError('Keyring: Expecting name to be a string.')
    }

    if (false === this.writable) {
      throw new TypeError('Keyring: Not writable')
    }

    const { storage, lock } = this
    const keyring = this
    const nonce = this.nonce.slice(0, 24)
    const hash = this.hash(name)
    const key = this.key.slice(0, 32)

    const stream = crypto.createBoxStream({ nonce, key })

    let buffer = null
    let length = 0

    lock(onlock)

    return stream

    function onerror(err) {
      stream.emit('error', err)
    }

    function ondone(err) {
      if (err) {
        onerror(err)
      } else {
        stream.emit('put', name, hash)
      }
    }

    function onlock(release) {
      collect(stream, oncollect)

      function oncollect(err, buf) {
        if (err) {
          release(ondone, err)
        } else {
          buffer = buf
          keyring.stat(onstat)
        }
      }

      function onstat(err, stat) {
        if (err) {
          release(ondone, err)
        } else {
          length = stat.size

          // len + hash + contents
          const len = crypto.uint64.encode(buffer.length)
          const entry = Buffer.allocUnsafe(8 + 8 + buffer.length)
          let offset = length

          if (0 === offset) {
            offset = kSignatureSize
          }

          len.copy(entry, 0)
          hash.copy(entry, 8)
          buffer.copy(entry, 8 + 8)

          storage.write(offset, entry, onwrite)
        }
      }

      function onwrite(err) {
        if (err) {
          release(ondone, err)
        } else {
          computeSignature(keyring, onsignature)
        }
      }

      function onsignature(err, signature) {
        release(ondone, err)

        if (signature && signature.length) {
          keyring.emit('signature', signature)
        }
      }
    }
  }
}

/**
 * Computes and writes an ed25519 signature using a keyring's secret key
 * and the computed Merkle roots for a key ring. The signature is stored in
 * the keyring's storage at offset 0 and is 64 bytes wide.
 * @private
 * @param {Keyring} keyring
 * @param {Function} cb
 */
function computeSignature(keyring, cb) {
  const { storage, secretKey } = keyring

  return computeRoots(keyring, onroots)

  function onroots(err, roots) {
    if (err) {
      cb(err)
    } else if (roots && roots.length) {
      if (secretKey) {
        const signature = crypto.ed25519.sign(roots, keyring.secretKey)
        storage.write(0, signature, onwrite)
      } else {
        onwrite(null)
      }
    } else {
      process.nextTick(cb, null, null)
    }
  }

  function onwrite(err) {
    if (err) {
      cb(err)
    } else {
      keyring.stat(onstat)
    }
  }

  function onstat(err, stat) {
    if (err) {
      cb(err)
    } else if (stat.size >= kSignatureSize) {
      storage.read(0, kSignatureSize, cb)
    } else {
      process.nextTick(cb, null, null)
    }
  }
}

/**
 * Computes the merkle tree roots of the keys found in
 * a key ring.
 * @private
 * @param {Keyring} keyring
 * @param {Function} cb
 */
function computeRoots(keyring, cb) {
  const { storage } = keyring
  const t = tree()

  // read first entry header after where signature will be
  let off = kSignatureSize
  process.nextTick(seek, kHeaderSize)

  function seek(size, next) {
    keyring.stat(onstat)

    function onstat(err, stat) {
      if (err) {
        cb(err)
      } else if (off + size < stat.size) {
        storage.read(off, size, next || onread)
        off += size
      } else {
        const roots = Buffer.concat(t.roots.map(({ hash }) => hash))
        cb(null, roots)
      }
    }
  }

  function onread(err, buf) {
    if (err) {
      cb(err)
    } else {
      const length = crypto.uint64.decode(buf)
      seek(length, onentry)
    }
  }

  function onentry(err, entry) {
    if (err) {
      cb(err)
    } else {
      t.next(entry)
      seek(kHeaderSize)
    }
  }
}

/**
 * Returns a Merkle tree generator that computes BLAKE2b
 * hashes of leaf and parent nodes.
 * @private
 * @return {Iterator}
 */
function tree() {
  return merkle({ leaf, parent })

  function leaf(node) {
    return crypto.blake2b(node.data)
  }

  function parent(left, right) {
    return crypto.blake2b(Buffer.concat([ left.hash, right.hash ]))
  }
}

// NO-OP
function noop() { }

/**
 * Ensures a callback for async functions.
 * @private
 */
function ensureCallback(cb) {
  return 'function' === typeof cb ? cb : noop
}

module.exports = {
  Keyring
}
