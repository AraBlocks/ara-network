/* eslint-disable import/no-extraneous-dependencies */
const { unpack, keyRing } = require('../../keys')
const { createChannel } = require('../../discovery/channel')
const { Handshake } = require('../../handshake')
const ss = require('ara-secret-storage')
const { readFile } = require('fs')
const { resolve } = require('path')
const { info } = require('ara-console')
const inquirer = require('inquirer')
const { DID } = require('did-uri')
const crypto = require('ara-crypto')
const pump = require('pump')
const pify = require('pify')
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
      describe: 'Path to ARA network keys'
    })

  if (argv.identity && 0 != argv.identity.indexOf('did:ara:')) {
    argv.identity = `did:ara:${argv.identity}`
  }

  conf.keys = argv.keys
  conf.name = argv.name
  conf.secret = argv.secret
  conf.identity = argv.identity
}

async function start() {
  channel = createChannel()

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
  const secretKey = ss.decrypt(keystore, { key: password.slice(0, 16) })

  const keyring = keyRing(conf.keys, { secret })
  const buffer = await keyring.get(conf.name)
  const unpacked = unpack({ buffer })

  const { discoveryKey } = unpacked

  channel.join(discoveryKey)
  channel.on('peer', onpeer)

  return true

  function onpeer(chan, peer) {
    const socket = net.connect(peer.port, peer.host)
    const handshake = new Handshake({
      publicKey,
      secretKey,
      secret,
      remote: { publicKey: unpacked.publicKey },
      domain: { publicKey: unpacked.domain.publicKey }
    })

    pump(handshake, socket, handshake)

    handshake.hello()
    handshake.on('hello', onhello)
    handshake.on('auth', onauth)
    handshake.on('okay', onokay)

    function onhello() {
      info('got HELLO')
      handshake.auth()
    }

    function onauth() {
      info('got AUTH')
    }

    function onokay() {
      info('got okay')
      const writer = handshake.createWriteStream()
      oninterval()
      setInterval(oninterval, 1000)
      function oninterval() {
        writer.write(Buffer.from('hello\n'))
      }
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
