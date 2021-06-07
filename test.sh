#!/bin/bash

set -e
set -u

# Pre-requisites:
# - jq: https://webinstall.dev/jq
# - keypairs: https://webinstall.dev/jq

source .env

echo ''
echo 'Expecting hello'
curl -fsSL http://localhost:"${PORT}"/hello
echo ''

echo ''
echo 'Expecting to exchange Google Token'
curl -sSL -v -X POST http://localhost:"${PORT}"/api/authn/session/oidc/google.com \
    -H "Authorization: Bearer ${GOOGLE_TEST_TOKEN}" |
    jq -r '.id_token'
my_access_token="$(
    curl -sSL -X POST http://localhost:"${PORT}"/api/authn/session/oidc/google.com \
        -H "Authorization: Bearer ${GOOGLE_TEST_TOKEN}" |
        jq -r '.id_token'
)"
echo "'${my_access_token}'"
keypairs inspect "${my_access_token}" > /dev/null
echo ''

echo ''
echo 'Expecting cookies and id_token'
curl -fsSL -X POST http://localhost:"${PORT}"/api/authn/session \
    -b cookies.jar -c cookies.jar \
    -H "Content-Type: application/json" \
    -d '{ "is_verified": true }'
echo ''

# Should give error
echo ''
echo 'Expecting Error:'
curl -sSL -X POST http://localhost:"${PORT}"/api/authn/refresh \
    -b cookies.jar -c cookies.jar |
    jq -r '.id_token'
echo ''

curl -sSL -v -X POST http://localhost:"${PORT}"/api/authn/refresh
my_token="$(
    curl -sSL -X POST http://localhost:"${PORT}"/api/authn/refresh \
        -b cookies.jar -c cookies.jar |
        jq -r '.id_token'
)"
echo ''
echo "Expecting new id_token"
echo "${my_token}"

echo ''
echo 'Expecting new access_token'
my_access_token="$(
    curl -sSL -X POST http://localhost:"${PORT}"/api/authn/exchange \
        -H "Authorization: Bearer ${my_token}" |
        jq -r '.access_token'
)"
echo "'${my_access_token}'"
keypairs inspect "${my_access_token}"
echo ''

echo 'PASS'
