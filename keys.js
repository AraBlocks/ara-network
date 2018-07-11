const isBuffer = require('is-buffer')
const crypto = require('ara-crypto')

/**
 * Supported packed binary formats in this module
 * @public
 */
const VERSION0 = 0x0
const VERSION = VERSION0

/**
 * `PKX` is the magic byte prepended to packed public network
 * keys binary.
 *
 * `SKX` is the magic byte prepended to packed secret network
 * keys binary.
 *
 * @public
 */
const PKX = 0x70
const SKX = 0x73

/**
 * Header sizes for packed binary
 *
 * @public
 */
const HEADER_SIZE0 = 1 + 1 + 32 + 32
const HEADER_SIZE = HEADER_SIZE0

/**
 * Public and network network key sizes,
 * including the header size.
 *
 * @public
 */
const PK_SIZE0 = HEADER_SIZE0 + 32
const SK_SIZE0 = HEADER_SIZE0 + 32
const PK_SIZE = PK_SIZE0
const SK_SIZE = SK_SIZE0

/**
 * Pack keys into a compact buffer.
 *
 * @public
 * @see {@link pack0}
 * @param {Object} opts
 * @param {?(Number)} [opts.version = VERSION]
 * @return {Buffer}
 * @throws TypeError
 */
function pack(opts) {
  if (!opts || 'object' !== typeof opts) {
    throw new TypeError('pack: Expecting object')
  }

  const V = 'number' === typeof opts.version ? opts.version : VERSION

  if (Number.isNaN(V)) {
    throw new TypeError(`pack: Invalid version: ${V}`)
  } else if (V < 0) {
    throw new TypeError(`pack: Version cannot be signed: ${V}`)
  } else if (V > 0xff) {
    throw new TypeError(`pack: Version out of range: 0 <= ${V} < ${0xff}`)
  }

  if (V === VERSION0) {
    return pack0(opts)
  }

  throw new TypeError(`pack: Unsupported version ${V}`)
}

/**
 * Version `0` binary packing format
 *   pack(T, V, D, B, K) = T|V|D|B_public_|K(T)
 *     where
 *     K(T) = 0x73 === T ? K_secret_ : K_public_
 *
 * @public
 * @param {Object} opts
 * @param {Number} opts.type
 * @param {Object} opts.domain
 * @param {Object} opts.publicKey
 * @param {Buffer} opts.discoveryKey
 * @return {Buffer}
 * @throws TypeError
 */
function pack0(opts) {
  if (!opts || 'object' !== typeof opts) {
    throw new TypeError('pack: Expecting object')
  }

  const V = VERSION0
  const T = opts.type
  const K = opts.domain
  const B = opts.publicKey
  const D = opts.discoveryKey
  const buffer = []

  if (PKX !== T && SKX !== T) {
    throw unknownTypeError('pack', T)
  }

  // + 1 + 1
  buffer.push(Buffer.from([T]))
  buffer.push(Buffer.from([V]))

  if (!D || false === isBuffer(D)) {
    throw new TypeError('pack: Invalid discovery key')
  } else if (32 !== D.length) {
    throw new TypeError(`pack: Bad discovery key length: ${D.length}`)
  }

  // + 32
  buffer.push(D)

  if (!B || false === isBuffer(B)) {
    throw new TypeError('pack: Invalid public key pair')
  } else if (32 !== B.length) {
    throw new TypeError(`pack: Bad public key length: ${B.length}`)
  }

  // + 32
  buffer.push(B)

  if (!K) {
    throw new TypeError('pack: Missing domain keys')
  } else if (T === SKX && isBuffer(K.secretKey)) {
    // + 32
    buffer.push(K.secretKey)
  } else if (T === PKX && isBuffer(K.publicKey)) {
    // + 32
    buffer.push(K.publicKey)
  } else {
    throw new TypeError('pack: Missing domain key')
  }

  const packed = Buffer.concat(buffer)
  const { length } = packed

  if (T === PKX && PK_SIZE0 !== length) {
    throw new TypeError(`pack: Pack error: invalid packed length: ${length}`)
  }

  if (T === SKX && SK_SIZE0 !== length) {
    throw new TypeError(`pack: Pack error: invalid packed length: ${length}`)
  }

  return packed
}

/**
 * Unpack binary buffer network keys.
 *
 * @public
 * @see {@link unpack0}
 * @param {Object} opts
 * @param {Buffer} buffer
 * @return {Object}
 * @throws TypeError
 */
function unpack(opts) {
  if (!opts || 'object' !== typeof opts) {
    throw new TypeError('unpack: Expecting object')
  } else if (!opts.buffer || false === isBuffer(opts.buffer)) {
    throw new TypeError('unpack: Expecting buffer')
  }

  const unpacked = {
    discoveryKey: null,
    publicKey: null,
    domain: { publicKey: null, secretKey: null },
  }

  seek(opts.buffer)
  return unpacked

  function seek(Z) {
    const T = Z[0]
    const V = Z[1]

    if (T !== PKX && T !== SKX) {
      throw unknownTypeError('unpack', T)
    }

    if (Number.isNaN(V)) {
      throw new TypeError(`unpack: Invalid version: ${V}`)
    } else if (V < 0) {
      throw new TypeError(`unpack: Version cannot be signed: ${V}`)
    } else if (V > 0xff) {
      throw new TypeError(`unpack: Version out of range: 0 <= ${V} < ${0xff}`)
    }

    if (V === VERSION0) {
      const offset = T === PKX ? PK_SIZE0 : SK_SIZE0
      const buffer = Z.slice(0, offset)
      const { discoveryKey, publicKey, domain } = unpack0({ buffer })

      // merge
      unpacked.discoveryKey = discoveryKey || unpacked.discoveryKey
      unpacked.publicKey = publicKey || unpacked.publicKey
      unpacked.domain.publicKey = domain.publicKey || unpacked.domain.publicKey
      unpacked.domain.secretKey = domain.secretKey || unpacked.domain.secretKey

      // keep reading
      if (offset < Z.length) {
        seek(Z.slice(offset))
      }
    }
  }
}

/**
 * Version `0` binary unpacking format.
 *   > HEADER ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ > BODY ~~~~~~~~
 *   | 1 byte      | 1 byte  | 32 bytes  | 32 bytes  | 32 bytes    |
 *   | ----------- | ------- | --------- | --------- | ----------- |
 *   | (T=PKX|SKX) |  (V=0)  |  (D=...)  |  (B=...)  |  (K=Kp|Ks)  |
 *   | ----------- | ------- | --------- | --------- | ----------- |
 *
 * @public
 * @param {Object} opts
 * @param {Buffer} buffer
 * @return {Object}
 * @throws TypeError
 */
function unpack0(opts) {
  if (!opts || 'object' !== typeof opts) {
    throw new TypeError('unpack: Expecting object')
  } else if (!opts.buffer || false === isBuffer(opts.buffer)) {
    throw new TypeError('unpack: Expecting buffer')
  }

  // Zi - current buffer offset
  read.i = 0

  // unpacked result for (T, V, D, Bp, K[ps])
  const unpacked = {
    discoveryKey: null,
    publicKey: null,
    domain: {
      publicKey: null,
      secretKey: null,
    },
  }

  // header= T|V|D|B (1+1+32+32)
  const Z = opts.buffer

  // packed binary type
  const T = read(1)[0]

  if (T !== PKX && T !== SKX) {
    throw unknownTypeError('unpack', T)
  }

  // packed binary version
  const V = read(1)[0]

  if (V !== VERSION0) {
    throw new TypeError(`unpack: Unsupported version ${V}`)
  }

  // discovery key
  const D = read(32)

  // public key
  const B = read(32)

  unpacked.discoveryKey = D
  unpacked.publicKey = B

  if (T === PKX) {
    unpacked.domain.publicKey = read(32)
  } else if (T === SKX) {
    unpacked.domain.secretKey = read(32)
  }

  return unpacked

  function read(size) {
    /* eslint-disable no-return-assign */
    return Z.slice(read.i, read.i += size)
  }
}

/**
 * Encrypts packed network keys into a secret storage based on
 * some shared key along with a secret key.
 * @public
 * @param {Object} opts
 * @param {Buffer} opts.buffer
 * @param {Buffer} opts.secret
 * @param {Buffer} opts.secretKey
 * @return {Object}
 * @throws TypeError
 */
function encrypt(opts) {
  if (!opts || 'object' !== typeof opts) {
    throw new TypeError('encrypt: Expecting object')
  }

  const Z = opts.buffer
  const V = Z[1]

  if (Number.isNaN(V)) {
    throw new TypeError(`encrypt: Invalid version: ${V}`)
  } else if (V < 0) {
    throw new TypeError(`encrypt: Version cannot be signed: ${V}`)
  } else if (V > 0xff) {
    throw new TypeError(`encrypt: Version out of range: 0 <= ${V} < ${0xff}`)
  }

  if (V === VERSION0) {
    return encrypt0(opts)
  }

  throw new TypeError(`encrypt: Unsupported version ${V}`)
}

/**
 * Encrypts packed network keys into a secret storage based on
 * some shared key along with a secret key for a version 0 binary
 * format
 * @public
 * @param {Object} opts
 * @param {Buffer} opts.buffer
 * @param {Buffer} opts.secret
 * @param {Buffer} opts.secretKey
 * @return {Object}
 * @throws TypeError
 */
function encrypt0(opts) {
  if (!opts || 'object' !== typeof opts) {
    throw new TypeError('encrypt: Expecting object')
  }

  // secret key
  const Bs = opts.secretKey
  // constant shared secret
  const S = opts.secret
  // public or secret network keys
  const Z = opts.buffer
  // magic byte
  const T = Z[0]
  // ephemeral shared secret
  const s = crypto.blake2b(S, 32)
  // 128-bit initialization vector
  const iv = crypto.randomBytes(16)
  // 128-bit encryption key
  const key = Buffer.allocUnsafe(16)

  if (T === PKX) {
    // k = blake2b(S')
    crypto.blake2b(s, 16).copy(key)
  } else if (T === SKX) {
    // k = blake2b(S' . Bs)
    crypto.blake2b(Buffer.concat([s, Bs]), 16).copy(key)
  } else {
    throw unknownTypeError('encrypt', T)
  }

  const result = crypto.encrypt(Z, { key, iv })

  result.type = T

  key.fill(0)
  iv.fill(0)

  return result
}

/**
 * @public
 * @param {Object} opts
 * @param {Buffer} opts.buffer
 * @param {Buffer} opts.secret
 * @param {Buffer} opts.secretKey
 * @return {Object}
 * @throws TypeError
 */
function decrypt(storage, opts) {
  if (!storage || 'object' !== typeof storage) {
    throw new TypeError('decrypt: Expecting object')
  } else if (!opts || 'object' !== typeof opts) {
    throw new TypeError('decrypt: Expecting object')
  }

  const V = 'number' === typeof opts.version ? opts.version : VERSION

  if (Number.isNaN(V)) {
    throw new TypeError(`decrypt: Invalid version: ${V}`)
  } else if (V < 0) {
    throw new TypeError(`decrypt: Version cannot be signed: ${V}`)
  } else if (V > 0xff) {
    throw new TypeError(`decrypt: Version out of range: 0 <= ${V} < ${0xff}`)
  }

  if (V === VERSION0) {
    return decrypt0(storage, opts)
  }

  throw new TypeError(`decrypt: Unsupported version ${V}`)
}

/**
 * @public
 * @param {Object} opts
 * @param {Buffer} opts.buffer
 * @param {Buffer} opts.secret
 * @param {Buffer} opts.secretKey
 * @return {Object}
 * @throws TypeError
 */
function decrypt0(storage, opts) {
  if (!storage || 'object' !== typeof storage) {
    throw new TypeError('decrypt: Expecting object')
  } else if (!opts || 'object' !== typeof opts) {
    throw new TypeError('decrypt: Expecting object')
  }

  const Bs = opts.secretKey
  const S = opts.secret
  // derive storage type from options or directly from the storage object
  const T = opts.type || storage.type

  if (T !== PKX && T !== SKX) {
    throw unknownTypeError('decrypt', T)
  }

  const s = crypto.blake2b(S, 32)
  const key = Buffer.allocUnsafe(16)

  if (T === PKX) {
    // k = blake2b(S')
    crypto.blake2b(s, 16).copy(key)
  } else if (T === SKX) {
    // k = blake2b(S' . Bs)
    crypto.blake2b(Buffer.concat([s, Bs]), 16).copy(key)
  } else {
    throw unknownTypeError('decrypt', T)
  }

  const result = crypto.decrypt(storage, { key })

  return result
}

/**
 * Generates and packs public and secret networks keys for some
 * key pair (B)
 * @public
 * @param {Object} opts
 * @param {Buffer} opts.publicKey
 * @param {Buffer} opts.secretKey
 * @return {Buffer}
 * @throws TypeError
 */
function generate(opts) {
  if (!opts || 'object' !== typeof opts) {
    throw new TypeError('generate: Expecting object')
  }

  const V = 'number' === typeof opts.version ? opts.version : VERSION

  if (Number.isNaN(V)) {
    throw new TypeError(`generate: Invalid version: ${V}`)
  } else if (V < 0) {
    throw new TypeError(`generate: Version cannot be signed: ${V}`)
  } else if (V > 0xff) {
    throw new TypeError(`generate: Version out of range: 0 <= ${V} < ${0xff}`)
  }

  if (V === VERSION0) {
    return generate0(opts)
  }

  throw new TypeError(`generate: Unsupported version ${V}`)
}

/**
 * Generates and packs public and secret networks keys for some
 * key pair (B)
 * @public
 * @param {Object} opts
 * @param {Buffer} opts.secret
 * @param {Buffer} opts.publicKey
 * @param {Buffer} opts.secretKey
 * @return {Buffer}
 * @throws TypeError
 */
function generate0(opts) {
  if (!opts || 'object' !== typeof opts) {
    throw new TypeError('generate: Expecting object')
  }

  // constant B public key
  const Bp = opts.publicKey
  // constant B secret key
  const Bs = opts.secretKey
  // ephemeral B secret key
  const bs = crypto.blake2b(Bs, 32)
  // constant shared secret
  const S = opts.secret
  // ephemeral shared secret
  const s = crypto.blake2b(S, 32)
  // compute K seed
  const seed = crypto.blake2b(Buffer.concat([s, bs]), 32)
  // constant domain key pair from blake2b(s . bs)
  const K = crypto.curve25519.keyPair(seed)
  // constant discovery key from Kp
  const D = crypto.blake2b(K.publicKey, 32)
  // pack Z = Zp | Zs
  const Z = Buffer.concat([
    // public
    pack0({
      type: PKX,
      version: VERSION0,
      discoveryKey: D,
      publicKey: Bp,
      domain: K,
    }),

    // secret
    pack0({
      type: SKX,
      version: VERSION0,
      discoveryKey: D,
      publicKey: Bp,
      domain: K,
    }),
  ])

  if (Z.length !== PK_SIZE0 + SK_SIZE0) {
    throw new Error('generate: Failed to correctly generate network keys')
  }

  return Z
}

/**
 * Generate a network keys secret storage key pair.
 *
 * @public
 * @param {Object} opts
 * @return {Object}
 * @throws TypeError
 */
function keyPair(opts) {
  if (!opts || 'object' !== typeof opts) {
    throw new TypeError('keyPair: Expecting object')
  }

  const V = 'number' === typeof opts.version ? opts.version : VERSION

  if (Number.isNaN(V)) {
    throw new TypeError(`keyPair: Invalid version: ${V}`)
  } else if (V < 0) {
    throw new TypeError(`keyPair: Version cannot be signed: ${V}`)
  } else if (V > 0xff) {
    throw new TypeError(`keyPair: Version out of range: 0 <= ${V} < ${0xff}`)
  }

  if (V === VERSION0) {
    return keyPair0(opts)
  }

  throw new TypeError(`keyPair: Unsupported version ${V}`)
}

/**
 */
function keyPair0(opts) {
  if (!opts || 'object' !== typeof opts) {
    throw new TypeError('keyPair: Expecting object')
  }

  const buffer = generate0(opts)
  const publicKeys = encrypt0({
    secret: opts.secret,
    buffer: buffer.slice(0, PK_SIZE0),
  })

  const secretKeys = encrypt0({
    secret: opts.secret,
    buffer: buffer.slice(PK_SIZE0, PK_SIZE0 + SK_SIZE0),
    secretKey: opts.secretKey,
  })

  return { publicKeys, secretKeys }
}

function unknownTypeError(n, T) {
  return new TypeError(`${n}: Unknown type: 0x${parseInt(T, 10).toString(16)}`)
}

module.exports = {
  generate0,
  generate,

  keyPair0,
  keyPair,

  encrypt0,
  encrypt,

  decrypt0,
  decrypt,

  unpack0,
  unpack,

  pack0,
  pack,

  VERSION0,
  VERSION,
  PKX,
  SKX,

  HEADER_SIZE0,
  HEADER_SIZE,
  PK_SIZE0,
  SK_SIZE0,
  PK_SIZE,
  SK_SIZE,
}
