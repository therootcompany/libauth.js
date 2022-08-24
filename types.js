/**
 * @typedef LibAuth
 * @property {PromisifyHandler} promisifyHandler
 * @property {PromisifyErrHandler} promisifyErrHandler
 * @property {LibAuthGet} get
 * @property {LibAuthSet} set
 */

/**
 * @typedef LibAuthOpts
 * @property {String} accessMaxAge
 * @property {String} authnParam
 * @property {String} cookieName
 * @property {String} cookiePath
 * @property {String} idMaxAge
 * @property {String} issuer
 * x@property {String} magicSalt -
 * @property {String} refreshMaxAge
 * @property {String} sessionMaxAge
 * @property {String} trustedMaxAge
 */

//
// The Magic Code Gen/Verify Interface
//

/**
 * The Magic Code Generator and Validator
 *
 * @typedef MagicCodeGen
 * @property {MagicCodeGenerator} generate
 * @property {MagicCodeValidator} validate
 */

/**
 * @typedef {Function} MagicCodeGenerator
 * @param {MagicCodeOpts} opts
 * @returns {Promise<MagicParts>}
 */

/**
 * @typedef {Function} MagicCodeValidator
 * @param {MagicOrder} order
 * @param {MagicParams} params
 * @param {Number} [receiptByteCount]
 * @param {BufferEncoding} [receiptEncoding]
 * @returns {Promise<MagicValidations>}
 */

//
// The Magic Flow Interface
//

/**
 * @typedef MagicCodeFlow
 * @property {MagicFlowInit} initialize - Convert id, receipt, & code to an order
 * @property {MagicFlowValidate} assertValid
 * @property {MagicFlowRedeem} redeem
 * @property {MagicFlowFail} handleFailure
 * @property {MagicFlowCancel} cancel
 */

/**
 * @typedef {Function} MagicFlowInit
 * @param {MagicParts} parts
 * @param {MagicDevice} device
 * @param {MagicRequest} request
 * @returns {Promise<MagicOrder>}
 */

/**
 * @typedef {Function} MagicFlowValidate
 * @param {Boolean} verified
 * @param {MagicOrder} order
 * @param {MagicParams} params
 * @param {MagicDevice} device
 * @returns {Promise<Boolean>}
 * @throws
 */

/**
 * @typedef {Function} MagicFlowRedeem
 * @param {Boolean} verified
 * @param {MagicOrder} order
 * @param {MagicParams} params
 * @param {MagicDevice} device
 * @returns {Promise<MagicOrder>}
 * @throws
 */

/**
 * TODO change name to fail?
 *
 * @typedef {Function} MagicFlowFail
 * @param {MagicOrder} order
 * @param {MagicParams} params
 * @param {MagicDevice} device
 * @returns {Promise<MagicOrder>}
 * @throws
 */

/**
 * @typedef {Function} MagicFlowCancel
 * @param {MagicOrder} order
 * @param {MagicParams} params
 * @param {MagicDevice} device
 * @returns {Promise<MagicOrder>}
 * @throws
 */

//
// The Magic Storage Interface
//

/**
 * @typedef MagicCodeStore
 * @property {MagicCodeStoreGet} get
 * @property {MagicCodeStoreSet} set
 */

/**
 * @typedef {Function} MagicCodeStoreGet
 * @param {MagicParams & MagicRequest} order
 * @returns {Promise<MagicOrder>}
 */

/**
 * @typedef {Function} MagicCodeStoreSet
 * @param {MagicOrder} order
 * @returns {Promise<void>}
 */

/**
 * Makes the given route handler async/await and Promise friendly.
 *
 * @callback PromisifyHandler
 * @param {import('express').Handler} handler
 * @returns {import('express').Handler}
 */

// `@callback` is an alias for `@typeduf {Function}`
// See <https://stackoverflow.com/a/60643856>.

/**
 * Makes the given route error handler async/await and Promise friendly.
 *
 * @typedef {Function} PromisifyErrHandler
 * @param {import('express').ErrorRequestHandler} errHandler
 * @returns {import('express').ErrorRequestHandler}
 */

/**
 * Get a param from the request object.
 *
 * @typedef {Function} LibAuthGet
 * @param {import('express').Handler} req
 * @param {String} [key]
 * @returns {any}
 */

// TODO maybe use Record<String,String> instead of Object?

/**
 * Set a param on the request object.
 *
 * @typedef {Function} LibAuthSet
 * @param {import('express').Handler} req
 * @param {String|Object} key
 * @param {any} [value]
 * @returns {void}
 */

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
 * @typedef MagicIdentifier
 * @property {String} [issuer]
 * @property {String} [type]
 * @property {String} [value]
 */

/**
 * @typedef {Object} MagicRequest
 * @property {any} custom
 * @property {String} duration
 * @property {MagicIdentifier} identifier
 * @property {any} state
 */

/**
 * @typedef {Object} MagicDevice
 * @property {String} ip
 * @property {String} userAgent
 */

/**
 * @typedef {Object} MagicParams
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
 * @typedef Challenge
 * @property {String} code
 * @property {MagicDevice} device
 * @property {MagicOrder} order
 * @property {MagicParams} params
 * @property {MagicRequest} request
 * @property {MagicStatus} [status]
 * @property {MagicValidations} validations
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
 * @returns {MagicParts}
 */

/**
 * @typedef MagicOrder
 * @property {String} id
 * @property {String} receipt
 * @property {MagicIdentifier} identifier
 * @property {any} [state]
 * @property {any} [custom] - TODO
 * @property {Number} attempts
 * @property {String} [deleted_at]
 * @property {String} duration
 * @property {String} expires_at
 * @property {String} [canceled_at]
 * @property {String} [canceled_by]
 * @property {String} [canceled_ip]
 * @property {String} [exchanged_at]
 * @property {String} [finalized_at]
 * @property {String} ordered_at
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
 * @property {String} [deleted_at]
 * @property {String} [duration]
 * @property {String} [expires_at]
 * @property {String} [canceled_at]
 * @property {String} [canceled_by]
 * @property {String} [exchanged_at]
 * @property {String} [finalized_at]
 * @property {String} [ordered_at]
 * @property {String} [ordered_by]
 * @property {String} [verified_at]
 * @property {String} [verified_by]
 */

/**
 * @typedef MagicValidations
 * @property {Boolean?} code
 * @property {Boolean?} receipt
 * @property {Boolean} valid
 */
