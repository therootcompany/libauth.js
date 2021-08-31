/**
 * @typedef JwsPriv
 * @param {string} d
 * @param {string} [dp]
 * @param {string} [dq]
 * @param {string} [p]
 * @param {string} [q]
 * @param {string} [qi]
 * @param {string} [kid]
 * @param {string} kty
 * @param {string} [alg]
 * @param {string} [n]
 * @param {string} [e]
 * @param {string} [crv]
 * @param {string} [x]
 * @param {string} [y]
 * @param {boolean} [ext]
 * @param {Array<string>} [key_opts]
 */

/**
 * @typedef JwsPub
 * @param {string} [kid]
 * @param {string} kty
 * @param {string} [alg]
 * @param {string} [n]
 * @param {string} [e]
 * @param {string} [crv]
 * @param {string} [x]
 * @param {string} [y]
 * @param {boolean} [ext]
 * @param {Array<string>} [key_opts]
 */

/**
 * @typedef VerifyOptions
 * @param {JwsPub} [pub]
 * @param {string} iss
 * @param {boolean} [optional]
 * @param {string} [userParam]
 * @param {string} [claimsParam]
 * @param {string} [jwsParam]
 */
