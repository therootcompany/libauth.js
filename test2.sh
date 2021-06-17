#!/bin/bash
set -e
set -u

source .env

function order() {
    local my_challenge_token="$(
        curl -X POST http://localhost:${PORT}/api/authn/challenge/issue \
            -H 'Content-Type: application/json' \
            -d '{ "type": "email", "value": "coolaj86@gmail.com" }' |
            jq -r '.challenge_token'
    )"
    echo "challenge_token:"
    echo "${my_challenge_token}"
    echo ''

    echo ''
    curl "http://localhost:${PORT}/api/authn/challenge?challenge_token=${my_challenge_token}"
    echo ''
    echo ''
}

function finalize() {
    local my_secret="${1}"
    local my_challenge_token="${2}"

    echo ''
    curl "http://localhost:${PORT}/api/authn/challenge?token=${my_secret}"
    echo ''
    echo ''

    curl -X POST http://localhost:${PORT}/api/authn/challenge/complete \
        -H 'Content-Type: application/json' \
        -d '{ "token": "'${my_secret}'" }'
    echo ''
    echo ''

    echo ''
    curl "http://localhost:${PORT}/api/authn/challenge?challenge_token=${my_challenge_token}"
    echo ''
    echo ''

    echo ''
    curl -X POST http://localhost:${PORT}/api/authn/challenge/exchange \
        -H 'Content-Type: application/json' \
        -d '{ "challenge_token": "'${my_challenge_token}'" }'
    echo ''
    echo ''
}

#order
#finalize XXXXXXXXXXXXXXXXXXXXXX xxxx.yyyy.zzzz
finalize v42JOYrMlkFyBGcQmpbukg eyJ0eXAiOiJKV1QiLCJraWQiOiJhTk1VcFBxazFUaVdKNXZXeG5nWHRHbWhob0JNTmFGOFpmZkZSa1QyWVBrIiwiYWxnIjoiRVMyNTYifQ.eyJjaGFsbGVuZ2VfaWQiOiJrclp1YmQzQXBYK1VkRU5kTzlmZDFSIiwidHlwZSI6ImVtYWlsIiwidmFsdWUiOiJjb29sYWo4NkBnbWFpbC5jb20iLCJpYXQiOjE2MjM5NjQ5MjYsImV4cCI6MTYyMzk2ODUyNiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDozMDQyIn0.JOtdACMFvKFvIgbUMV1gRXzqHAHyC-MTOCr9VaiAjJeEKyEd9BF4TYuyIR3FplY9NKXFhVv1z1ZY5TfpRe19ZA
