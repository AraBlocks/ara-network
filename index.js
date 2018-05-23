'use strict'

const discovery = require('./discovery')
const signalhub = require('./signalhub')
const dht = require('./dht')
const dns = require('./dns')

module.exports = {
  discovery,
  signalhub,
  dht,
  dns,
}
