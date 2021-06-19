#!/bin/bash
set -e
set -u

source .env

function order() {
    # 1. Order Verification Challenge 
    # Order a new email verification challenge
    # (an email will be sent that contains a secret code)
    local my_challenge_token="$(
        curl -X POST http://localhost:${PORT}/api/authn/challenge/issue \
            -H 'Content-Type: application/json' \
            -d '{ "type": "email", "value": "coolaj86@gmail.com" }' |
            jq -r '.challenge_token'
    )"
    # This challenge token can be used to check the status of the challenge order
    # (think of it as the receipt / tracking number)
    echo "challenge_token:"
    echo "${my_challenge_token}"
    echo ''

    # 2. Check Status of Challenge Order
    # We can check the challenge order and see that it is not yet fulfilled
    # (the user did not yet receive the email and click the secret link)
    echo ''
    curl "http://localhost:${PORT}/api/authn/challenge?challenge_token=${my_challenge_token}"
    echo ''
    echo ''
}

function finalize() {
    local my_secret="${1}"
    local my_challenge_token="${2}"

    # 3. Check (Secret) Status of Challenge Order
    # Here we are checking to see that the secret is still valid
    # (is not expired, has not been used - good for debugging)
    echo ''
    curl "http://localhost:${PORT}/api/authn/challenge?token=${my_secret}"
    echo ''
    echo ''

    # 4. Get ID Token: Verify Challenge / Finalize Order (with Secret) 
    # Here we finalize the order with the secret, and get back an id token
    # (the user clicks the link in the email)
    echo ''
    curl -X POST http://localhost:${PORT}/api/authn/challenge/complete \
        -H 'Content-Type: application/json' \
        -d '{ "token": "'${my_secret}'" }'
    echo ''
    echo ''

    # 5. Check Status of Challenge Order 
    # We check to see that the challenge token (which can only be used after
    # the secret has been provided from the email link) is usable. This is
    # the same thing we did up in step 2.
    echo ''
    curl "http://localhost:${PORT}/api/authn/challenge?challenge_token=${my_challenge_token}"
    echo ''
    echo ''

    # 6. Get ID Token (2): Exchange Challenge (non-secret) Token
    # We exchange the original non-secret challenge token for an id_token also
    # (this is for the case that the user clicked the email in a different browser
    # or device - such as their phone - than were they originally using)
    echo ''
    curl -X POST http://localhost:${PORT}/api/authn/challenge/exchange \
        -H 'Content-Type: application/json' \
        -d '{ "challenge_token": "'${my_challenge_token}'" }'
    echo ''
    echo ''
}

#order
#finalize XXXXXXXXXXXXXXXXXXXXXX xxxx.yyyy.zzzz
