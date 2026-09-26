#!/usr/bin/env bash
# Publishes the four @recon reconstruction fixtures to a local Verdaccio registry so the testbed
# can install them with `npm ci`, exactly as it would install a real dependency. Nothing is ever
# published to npmjs.com. Requires Docker.
set -euo pipefail

REGISTRY_PORT="${REGISTRY_PORT:-4873}"
REGISTRY_URL="http://localhost:${REGISTRY_PORT}/"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_DIR="${HERE}/../reconstructions"
CONTAINER="verdaccio-recon"

echo "Starting Verdaccio on ${REGISTRY_URL} ..."
docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
docker run -d --name "${CONTAINER}" -p "${REGISTRY_PORT}:4873" verdaccio/verdaccio:6 >/dev/null

echo "Waiting for the registry to accept connections ..."
for _ in $(seq 1 30); do
  if curl -fsS "${REGISTRY_URL}" >/dev/null 2>&1; then break; fi
  sleep 1
done

# Verdaccio allows self-registration by default; create a throwaway user and capture the token.
TOKEN="$(curl -fsS -X PUT "${REGISTRY_URL}-/user/org.couchdb.user:recon" \
  -H 'Content-Type: application/json' \
  -d '{"name":"recon","password":"recon12345"}' | node -e 'process.stdin.on("data",d=>{try{console.log(JSON.parse(d).token)}catch{}})')"

if [ -z "${TOKEN}" ]; then
  echo "Could not obtain a registry token." >&2
  exit 1
fi

NPMRC="$(mktemp)"
trap 'rm -f "${NPMRC}"' EXIT
{
  echo "registry=${REGISTRY_URL}"
  echo "//localhost:${REGISTRY_PORT}/:_authToken=${TOKEN}"
} > "${NPMRC}"

for pkg in p0-lifecycle p1-import-loader p2-sorted-btree p3-optional-helper; do
  echo "Publishing @recon/${pkg} ..."
  ( cd "${RECON_DIR}/${pkg}" && npm publish --userconfig "${NPMRC}" --registry "${REGISTRY_URL}" >/dev/null )
done

echo
echo "Done. Four @recon fixtures are on ${REGISTRY_URL}"
echo "The testbed's .npmrc routes the @recon scope there. To install the compromised testbed:"
echo "  cd testbed && npm install @recon/p1-import-loader @recon/p2-sorted-btree && npm ci"
echo "Stop the registry with:  docker rm -f ${CONTAINER}"
