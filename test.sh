#!/bin/bash

set -e
set -u
#set -o pipefail

# Pre-requisites:
# - jq: https://webinstall.dev/jq
# - keypairs: https://webinstall.dev/jq

source .env

echo ''
echo 'Expecting hello'
curl -fsSL http://localhost:"${PORT}"/hello
echo ''

echo ''
echo 'Logout: Expecting success even when not logged in:'
curl -fsSL -X DELETE http://localhost:"${PORT}"/api/authn/session
echo ''

echo ''
echo 'User Credentials: Expecting cookies and id_token'
curl -fsSL -X POST http://localhost:"${PORT}"/api/authn/session \
    -b cookies.jar -c cookies.jar \
    -H "Content-Type: application/json" \
    -d '{ "user": "coolaj86@gmail.com", "pass": "secret123" }'
echo ''

# Should give error
echo ''
echo 'No Cookies: Expecting Error:'
if ! curl -sSL -X POST http://localhost:"${PORT}"/api/authn/refresh |
    grep 'INVALID_SESSION'; then
    echo "Expected auth error"
    exit 1
fi
echo ''

echo ''
echo 'Recent Cookies: Expecting New Token:'
my_id_token="$(
    curl -fsSL -X POST http://localhost:"${PORT}"/api/authn/refresh \
        -b cookies.jar -c cookies.jar |
        jq -r '.id_token'
)"
echo "${my_id_token}"

echo ''
echo 'Exchange: Expecting new user access_token'
my_access_token="$(
    curl -fsSL -X POST http://localhost:"${PORT}"/api/authn/exchange \
        -H "Authorization: Bearer ${my_id_token}" \
        -H "Content-Type: application/json" \
        -d '{ "account_id": "Polo" }' |
        jq -r '.access_token'
)"
#echo "'${my_access_token}'"
# TODO add issue for keypairs exiting cleanly on error
keypairs inspect "${my_access_token}" > /dev/null
echo ''

echo ''
echo 'Logout: Expecting success when logged in:'
curl -fsSL -X DELETE http://localhost:"${PORT}"/api/authn/session \
    -b cookies.jar -c cookies.jar
echo ''

echo ''
echo 'Refresh: Expecting Error (logged out)'
if ! curl -sSL -X POST http://localhost:"${PORT}"/api/authn/refresh \
    -b cookies.jar -c cookies.jar |
    grep 'INVALID_SESSION'; then
    echo "Expected auth error"
    exit 1
fi
echo ''

if [[ -z ${GOOGLE_TEST_TOKEN:-} ]]; then
    echo >&2 ''
    echo >&2 '[SKIP] Google ID Token Test SKIPPED'
    echo >&2 ''
else
    echo ''
    echo 'Expecting to exchange Google Token'
    my_access_token="$(
        curl -fsSL -X POST http://localhost:"${PORT}"/api/authn/session/oidc/google.com \
            -H "Authorization: Bearer ${GOOGLE_TEST_TOKEN}" |
            jq -r '.id_token'
    )"
    echo "'${my_access_token}'"
    keypairs inspect "${my_access_token}" > /dev/null
    echo ''
fi

echo ''
echo 'Use Token: Inspect'
curl -fsSL http://localhost:"${PORT}"/api/debug/inspect \
    -H "Authorization: Bearer ${my_access_token}"
echo ''

echo ''
echo 'Use Token: List Dummies: Expecting Error'
if ! curl -sSL http://localhost:"${PORT}"/api/dummy \
    -H "Authorization: Bearer ${my_access_token}" | grep 'Unauthorized'; then
    echo "Expected auth error"
    exit 1
fi
echo ''

echo ''
echo 'Exchange: Expecting new admin access_token'
my_access_token="$(
    curl -fsSL -X POST http://localhost:"${PORT}"/api/authn/exchange \
        -H "Authorization: Bearer ${my_id_token}" \
        -H "Content-Type: application/json" \
        -d '{ "account_id": "Marko" }' |
        jq -r '.access_token'
)"

###################
#                 #
#  Admin Dummies  #
#                 #
###################

echo ''
echo 'Use Token: List Dummies'
curl -fsSL http://localhost:"${PORT}"/api/dummy \
    -H "Authorization: Bearer ${my_access_token}"
echo ''

echo ''
echo 'Use Token: Add New Dummies'
echo '['
curl -fsSL -X POST http://localhost:"${PORT}"/api/dummy \
    -H "Authorization: Bearer ${my_access_token}" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "AJ",
        "age": "30"
    }'
echo ','
my_result="$(
    curl -fsSL -X POST http://localhost:"${PORT}"/api/dummy \
        -H "Authorization: Bearer ${my_access_token}" \
        -H "Content-Type: application/json" \
        -d '{
        "name": "Aggie",
        "age": "24"
    }'
)"
echo "${my_result}"
my_id="$(echo "${my_result}" | jq -r '.id')"
echo ']'

echo ''
echo 'Use Token: List Dummies'
curl -fsSL http://localhost:"${PORT}"/api/dummy \
    -H "Authorization: Bearer ${my_access_token}"
echo ''

echo ''
echo "Use Token: Get Dummy ${my_id}"
curl -fsSL "http://localhost:${PORT}/api/dummy/${my_id}" \
    -H "Authorization: Bearer ${my_access_token}"
echo ''

##################
#                #
#  User Dummies  #
#                #
##################

echo ''
echo 'Exchange: Expecting new user access_token'
my_access_token="$(
    curl -fsSL -X POST http://localhost:"${PORT}"/api/authn/exchange \
        -H "Authorization: Bearer ${my_id_token}" \
        -H "Content-Type: application/json" \
        -d '{ "account_id": "Polo" }' |
        jq -r '.access_token'
)"
echo ''

echo ''
echo 'Expect Error: Add New Dummy'
if ! curl -sSL -X POST http://localhost:"${PORT}"/api/dummy \
    -H "Authorization: Bearer ${my_access_token}" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Ben",
        "age": "35"
    }' | grep Unauthorized; then
    echo "Expected admin error"
    exit 1
fi
echo ''

echo ''
echo "Use Token: Get Dummy ${my_id}"
curl -fsSL "http://localhost:${PORT}/api/dummy/${my_id}" \
    -H "Authorization: Bearer ${my_access_token}"
echo ''

echo ''
echo 'PASS'
