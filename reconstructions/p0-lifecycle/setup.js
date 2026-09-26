'use strict';
// Benign fixture (P0 control). Runs at install via postinstall, which npm v12 blocks by default.
// Inert: writes a marker and pings a non-resolving sinkhole.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

fs.writeFileSync(path.join(os.tmpdir(), 'recon-p0.marker'), `p0 ${new Date().toISOString()}\n`);
http.get('http://sinkhole.invalid/p0', () => {}).on('error', () => {});
