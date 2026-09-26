'use strict';
// Benign fixture (P3 silent optional dependency), same shape as the TanStack case: an optional
// dependency points at a non-registry source that fails to install quietly, and the package then
// reaches out at module scope. The lockfile check flags the optional non-registry source; the
// static layer flags the module-scope request. Inert: pings a non-resolving sinkhole. No payload.
const https = require('node:https');

let native;
try {
  native = require('@recon/p3-native-ext');
} catch {
  https.get('https://sinkhole.invalid/p3-fallback', () => {}).on('error', () => {});
  native = null;
}

module.exports.upper = (text) => (native ? native.upper(text) : String(text).toUpperCase());
