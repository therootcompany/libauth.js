/**
 * @typedef {Object} Jws
 * @property {string} [payload]
 * @property {string} [protected]
 * @property {string} [signature]
 * @property {any} [claims]
 * @property {Object.<string, any>} [headers]
 */

/**
 * Callback for adding two numbers.
 *
 * @callback tokenVerifier
 * @param {Jws} jws - A JWS (decoded JWT).
 * @returns Promise
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
 * @typedef {Object} OidcVerifyOpts
 * @property {function|boolean} [verify]
 * @property {function|boolean} [pluginVerify]
 * @property {string|boolean} [iss]
 * @property {string|boolean} [sub]
 * @property {string|boolean} [aud]
 * @property {string|boolean} [azp]
 * @property {string|boolean} [exp]
 * @property {string|boolean} [email]
 * @property {boolean} [email_verified]
 */

/**
 * @typedef {Object} Oauth2MiddlewareOpts
 * @property {String} clientId
 * @property {String} clientSecret
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

/**
 * The Magic Code Generator
 * @namespace MagicCodeGen
 */

/**
 * Finalizes and returns the "Magic Link" within the login flow.
 * @memberof MagicCodeGen
 * @name generate
 * @function
 * @param {Number} codeBytes
 * @param {String} codeEnc
 * @param {Number} idBytes
 * @param {String} idEnc
 * @return {MagicParts}
 */

/**
 * Finalizes and returns the "Magic Link" within the login flow.
 * @memberof MagicCodeGen
 * @name verify
 * @function
 * @param {MagicOrder} order
 * @param {String} code
 * @return {Boolean}
 */

/**
 * @typedef MagicIdentifier
 * @property {String} [issuer]
 * @property {String} [type]
 * @property {String} [value]
 */

/**
 * @typedef MagicRequest
 * @property {MagicIdentifier} identifier
 * @property {any} state
 */

/**
 * @typedef MagicDevice
 * @property {String} ip
 * @property {String} userAgent
 */

/**
 * @typedef MagicParams
 * @property {String} id
 * @property {String} [code]
 * @property {String} [receipt]
 * @property {Boolean} [finalize]
 * @property {MagicRequest} [request]
 * @property {MagicDevice} device
 */

/**
 * @typedef MagicParts
 * @property {String} id
 * @property {String} code
 * @property {String} receipt
 */

/**
 * @typedef MagicAssertOpts
 * @property {Boolean} [failedValidation]
 * @property {Boolean} requireExchange
 * @property {Number} [timestamp]
 */

/**
 * @typedef MagicVerifierOpts
 * @property {String} duration
 * @property {Number} maxAttempts
 */

/**
 * @typedef MagicCodeOpts
 * @property {String} magicSalt
 * @property {Number} codeByteCount
 * @property {BufferEncoding} codeEncoding
 * @property {Number} idByteCount
 * @property {BufferEncoding} idEncoding
 * @property {Number} receiptByteCount
 * @property {BufferEncoding} receiptEncoding
 */

/**
 * @typedef MagicOrder
 * @property {String} id
 * @property {String} [receipt]
 * @property {MagicIdentifier} [identifier]
 * @property {any} [state]
 * @property {Number} attempts
 * @property {String} [duration]
 * @property {String} [expires_at]
 * @property {String} [canceled_at]
 * @property {String} [canceled_by]
 * @property {String} [canceled_ip]
 * @property {String} [exchanged_at]
 * @property {String} [ordered_at]
 * @property {String} [ordered_by]
 * @property {String} [ordered_ip]
 * @property {String} [verified_at]
 * @property {String} [verified_by]
 * @property {String} [verified_ip]
 */

/**
 * @typedef MagicStatus
 * @property {String} id
 * @property {String} [receipt]
 * @property {String} status
 * @property {any} [state]
 * @property {String} [duration]
 * @property {String} [expires_at]
 * @property {String} [canceled_at]
 * @property {String} [canceled_by]
 * @property {String} [exchanged_at]
 * @property {String} [ordered_at]
 * @property {String} [ordered_by]
 * @property {String} [verified_at]
 * @property {String} [verified_by]
 */

/**
 * @typedef MagicResponse
 * @property {MagicOrder} order
 * @property {MagicStatus} status
 */
