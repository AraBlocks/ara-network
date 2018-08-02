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

    if (storage && 'object' !== typeof storage) {
      if ('string' === typeof storage) {
        // eslint-disable-next-line no-param-reassign
        storage = raf(storage)
      } else if ('function' === typeof storage) {
        // eslint-disable-next-line no-param-reassign
        storage = storage(this, opts)
      } else {
        // eslint-disable-next-line function-paren-newline
        throw TypeError(
          'Keyring: Expecting storage to be an object, string, or function.')
      }
    }

    this.setMaxListeners(0)

    if (isBuffer(opts.secret)) {
      this.key = opts.secret.slice(0, 32)
      this.nonce = opts.secret.slice(32)
    }

    if (isBuffer(opts.nonce)) {
      this.nonce = opts.nonce
    }

    if (isBuffer(opts.key)) {
      this.key = opts.key
    }

    if (false === isBuffer(this.nonce)) {
      throw new TypeError('Keyring: Expecting nonce to be a buffer.')
    }

    const keyring = this
    const seed = this.secret.slice(0, 32)

    const { publicKey, secretKey } = crypto.ed25519.keyPair(seed)

    this.publicKey = publicKey
    this.secretKey = secretKey
    this.storage = storage
    this.lock = mutex()

    if (true === opts.readonly) {
      this.storage.preferReadonly = true
    } else {
      this.storage.preferReadonly = false
    }

    this.storage.open(onopen)

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
   * Will be true if the keyring storage is writable
   * @public
   * @accessor
   * @type {Boolean}
   */
  get writable() {
    return this.storage.writable
  }

  /**
   * Will be true if the keyring storage is readable
   * @public
   * @accessor
   * @type {Boolean}
   */
  get readable() {
    return this.storage.readable
  }

  /**
   * Computes the short hash (SipHash) of a keyring entry name.
   * @public
   * @param {String} namek
   * @return {Buffer}
   */
  hash(name) {
    const buf = Buffer.from(name || [ 0x0 ])
    return crypto.shash(buf, this.secretKey.slice(0, 16))
  }

  /**
   * Reads the 64 byte keyring signature, if computed.
   * @public
   * @param {Function} cb
   */
  proof(cb) {
    this.stat((err, stat) => {
      if (err) {
        cb(err)
      } else if (stat.size >= kSignatureSize) {
        this.storage.read(0, kSignatureSize, cb)
      } else {
        cb(null, null)
      }
    })
  }

  /**
   * Get the size of the keyring storage.
   * @public
   * @param {Function} cb
   */
  stat(cb) {
    if ('number' === typeof this.storage.length) {
      process.nextTick(cb, null, { size: this.storage.length })
    } else if (this.storage.statable) {
      this.storage.stat(cb)
    } else {
      process.nextTick(cb, null, { size: 0 })
    }
  }

  /**
   * Appends a key to the keyring by name. This function
   * will compute Merkle root nodes and rewrite the keyring
   * signature.
   * @public
   * @param {String} name
   * @param {Buffer} key
   * @param {Function} cb
   * @emits append
   */
  append(name, key, cb) {
    const stream = this.createWriteStream(name)
    const parts = split(key, 4 * 1024)

    stream.once('put', cb)
    stream.once('put', () => this.emit('append', name))

    for (const part of parts) {
      stream.write(part)
    }

    stream.end()
  }

  /**
   * Gets a keyring by name.
   * @public
   * @param {String} name
   * @param {Function} cb
   */
  get(name, cb) {
    const stream = this.createReadStream(name)
    collect(stream, cb)
  }

  /**
   * Determine if named key has access in underlying storage.
   * @public
   * @param {String} name
   * @param {Function} cb
   */
  access(name, cb) {
    this.get(name, onget)

    function onget(err, entry) {
      if (err) {
        cb(err)
      } else if (!entry || 0 === entry.length) {
        cb(new Error(`Keyring: No such entry exists: '${name}'`))
      } else {
        cb(null)
      }
    }
  }

  /**
   * Determine if keyring has a named key.
   * @public
   * @param {String} name
   * @param {Function} cb
   */
  has(name, cb) {
    this.access(name, onaccess)
    function onaccess(err) {
      cb(null, null === err)
    }
  }

  /**
   * Computes the Merkle tree roots for this keyring
   * at the current state of the storage.
   * @public
   * @param {Function} cb
   */
  computeRoots(cb) {
    computeRoots(this, cb)
  }

  /**
   * Computes and writes an ed25519 signature using a keyring's secret key
   * and the computed Merkle roots for a key ring. The signature is stored in
   * the keyring's storage at offset 0 and is 64 bytes wide.
   * @public
   * @param {Function} cb
   */
  computeSignature(cb) {
    computeSignature(this, cb)
  }

  /**
   * Creates a read stream that unboxes an encrypted key found in
   * the underlying storage by name and provides it as a stream.
   * @public
   * @param {String} name
   * @throws TypeError
   */
  createReadStream(name) {
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

module.exports = {
  Keyring
}
