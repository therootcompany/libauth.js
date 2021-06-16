source .env

function order() {
    curl -X POST http://localhost:${PORT}/api/authn/challenge/issue \
        -H 'Content-Type: application/json' \
        -d '{ "type": "email", "value": "coolaj86@gmail.com" }'
    echo ''
}

function finalize() {
    my_secret="${1}"
    echo ''
    curl "http://localhost:${PORT}/api/authn/challenge?token=${my_secret}"
    echo ''
    echo ''

    curl -X POST http://localhost:${PORT}/api/authn/challenge/complete \
        -H 'Content-Type: application/json' \
        -d '{ "token": "'${my_secret}'" }'
    echo ''
    echo ''
}

#order
finalize R70gjeDLltGo4iKOjL52Vg
