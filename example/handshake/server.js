/* eslint-disable import/no-extraneous-dependencies */
const { unpack, keyRing } = require('../../keys')
const { createChannel } = require('../../discovery/channel')
const { info, warn } = require('ara-console')
const { Handshake } = require('../../handshake')
const { readFile } = require('fs')
const { resolve } = require('path')
const inquirer = require('inquirer')
const { DID } = require('did-uri')
const crypto = require('ara-crypto')
const pify = require('pify')
const pump = require('pump')
const net = require('net')
const rc = require('../../rc')()

const conf = {}
let channel = null

async function getInstance() {
  return channel
}

async function configure(opts, program) {
  const { argv } = program
    .option('identity', {
      alias: 'i',
      describe: 'ARA identity for this network node. (Requires password)'
    })
    .option('secret', {
      alias: 's',
      describe: 'Shared secret key for network keys associated with this node.'
    })
    .option('name', {
      alias: 'n',
      describe: 'Human readable network keys name.'
    })
    .option('keys', {
      alias: 'k',
      describe: 'Path to keyring'
    })
    .option('port', {
      alias: 'p',
      default: 3000,
      describe: 'Port this node should connect on.'
    })

  if (argv.identity && 0 !== argv.identity.indexOf('did:ara:')) {
    argv.identity = `did:ara:${argv.identity}`
  }

  conf.port = argv.port
  conf.keys = argv.keys
  conf.name = argv.name
  conf.secret = argv.secret
  conf.identity = argv.identity
}

async function start() {
  channel = createChannel({ })

  let { password } = await inquirer.prompt([ {
    type: 'password',
    name: 'password',
    message:
    'Please enter the passphrase associated with the node identity.\n' +
    'Passphrase:'
  } ])

  const did = new DID(conf.identity)
  const publicKey = Buffer.from(did.identifier, 'hex')

  password = crypto.blake2b(Buffer.from(password))

  const hash = crypto.blake2b(publicKey).toString('hex')
  const path = resolve(rc.network.identity.root, hash, 'keystore/ara')
  const secret = Buffer.from(conf.secret)
  const keystore = JSON.parse(await pify(readFile)(path, 'utf8'))
  const secretKey = crypto.decrypt(keystore, { key: password.slice(0, 16) })

  const keyring = keyRing(conf.keys, { secret: secretKey })
  const buffer = await keyring.get(conf.name)
  const unpacked = unpack({ buffer })

  const { discoveryKey } = unpacked
  const server = net.createServer(onconnection)

  server.listen(conf.port, onlisten)

  return true

  function onlisten(err) {
    if (err) { throw err }
    const { port } = server.address()
    channel.join(discoveryKey, port)
  }

  function onconnection(socket) {
    const handshake = new Handshake({
      publicKey,
      secretKey,
      secret,
      remote: { publicKey: unpacked.publicKey },
      domain: { publicKey: unpacked.domain.publicKey }
    })

    handshake.on('hello', onhello)
    handshake.on('auth', onauth)
    handshake.on('okay', onokay)

    pump(handshake, socket, handshake, (err) => {
      if (err) {
        warn(err.message)
      } else {
        info('connection closed')
      }
    })

    function onhello() {
      info('got HELLO')
      handshake.hello()
    }

    function onauth() {
      info('got AUTH')
    }

    function onokay() {
      info('got OKAY', handshake.state.phase)
      const reader = handshake.createReadStream()
      // socket.pipe(process.stdout)
      reader.pipe(process.stdout)
    }
  }
}

async function stop() {
  channel.destroy()
}

module.exports = {
  getInstance,
  configure,
  start,
  stop,
}
