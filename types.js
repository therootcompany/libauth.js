/**
 * @typedef {Object} Jws
 * @property {string} [payload]
 * @property {string} [protected]
 * @property {string} [signature]
 * @property {any} [claims]
 * @property {Object.<string, any>} [headers]
 */

/**
 * @typedef {Object} AuthN
 * @property {string} [strategy]
 * @property {string} [type]
 * @property {string} [value]
 * @property {string} [code]
 * @property {string} [secret]
 * @property {string} [id]
 * @property {string} [ppid]
 * @property {string} [issuer]
 * @property {string} [iss]
 */

/**
 * @typedef Challenge
 * @property {number} attempts
 * @property {string} secret // TODO rename to code
 * @property {string} code
 * @property {string} ordered_at
 * @property {string} ordered_by // TODO rename _agent
 * @property {string} ordered_ip
 * @property {string} verified_at // RFC3339 / ISO Timestamp
 * @property {string} verified_by
 * @property {string} verified_ip
 * @property {string} exchanged_at
 * @property {string} exchanged_by
 * @property {string} exchanged_ip
 * @property {string} canceled_at
 * @property {string} canceled_by
 * @property {string} canceled_ip
 * @property {string} deleted_at
 * @property {string} type // such as 'email' or 'tel'
 * @property {string} value // such as 'me@example.com'
 */

/**
 * @typedef {Object} JwsPriv
 * @property {string} d
 * @property {string} [dp]
 * @property {string} [dq]
 * @property {string} [p]
 * @property {string} [q]
 * @property {string} [qi]
 * @property {string} [kid]
 * @property {string} kty
 * @property {string} [alg]
 * @property {string} [n]
 * @property {string} [e]
 * @property {string} [crv]
 * @property {string} [x]
 * @property {string} [y]
 * @property {boolean} [ext]
 * @property {Array<string>} [key_opts]
 */

/**
 * @typedef {Object} JwsPub
 * @property {string} [kid]
 * @property {string} kty
 * @property {string} [alg]
 * @property {string} [n]
 * @property {string} [e]
 * @property {string} [crv]
 * @property {string} [x]
 * @property {string} [y]
 * @property {boolean} [ext]
 * @property {Array<string>} [key_opts]
 */

/**
 * @typedef {Object} MyIdClaims
 * @property {string} [jti]
 * @property {string} [sub]
 * @property {string|number} [exp]
 * @property {string} email
 * @property {boolean} email_verified
 * @property {string} given_name
 * @property {string} family_name
 */

/**
 * @typedef {Object} MyAccessClaims
 * @property {string} [jti]
 * @property {string} [sub]
 * @property {string|number} [exp]
 * @property {string} account_id
 * @property {string} [impersonator_id]
 * @property {string} [effective_id]
 * @property {Array<string>} [scope]
 */

/**
 * @typedef {any} MyClaims
 */

/**
 * @typedef {any} MyAllClaims
 * @property {Claims} [claims]
 * @property {IdClaims} [id_claims]
 * @property {AccessClaims} [access_claims]
 * @property {RefreshClaims} [access_claims]
 */

/**
 * @typedef {Object} OidcVerifyOpts
 * @property {string} [iss]
 * @property {string|boolean} [exp]
 */

/**
 * @typedef {Object} OidcMiddlewareOpts
 * @property {import('express').Router} app
 * @property {any} opts
 * @property {function} _strategyHandler
 * @property {function} grantTokensAndCookie
 * @property {function} verifyOidcToken
 */

/**
 * @typedef {Object} Oauth2MiddlewareOpts
 * @property {import('express').Router} app
 * @property {any} opts
 * @property {function} _strategyHandler
 * @property {function} grantTokensAndCookie
 */

/**
 * @typedef {Object} VerifyOptions
 * @property {JwsPub} [pub]
 * @property {string} iss
 * @property {boolean} [optional]
 * @property {string} [userParam]
 * @property {string} [claimsParam]
 * @property {string} [jwsParam]
 */
