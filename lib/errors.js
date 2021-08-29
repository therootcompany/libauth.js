"use strict";

// Possible User Errors

/**
 * @typedef MyAuthError
 * @property {string} message
 * @property {number} status
 * @property {string} code
 * @property {any} [details]
 */

/** @typedef {MyAuthError & Error} AuthError */

/**
 * @returns {AuthError}
 */
function CODE_RETRY() {
  let err = new Error(
    "That verification code isn't correct. It may have been mistyped or the URL may not have been copied completely."
  );
  err.message = err.message;
  err.status = 400;
  err.code = "E_CODE_RETRY";
  return err;
}

/**
 * @param {string} [type]
 * @returns {AuthError}
 */
function UNVERIFIED_OIDC_IDENTIFIER(type = "identifier") {
  let err = new Error(
    `You cannot use the ${type} associated with this account because you haven't completed the verification yet.`
  );
  err.message = err.message;
  err.status = 400;
  err.code = "E_UNVERIFIED_OIDC_IDENTIFIER";
  return err;
}

// Ambi-Errors - could be the result of user or developer error

/**
 * @returns {AuthError}
 */
function CODE_INVALID() {
  let err = new Error(
    "That verification code isn't valid. It might have been used previously, or might be expired, tried to many times, or just may not exist at all."
  );
  err.message = err.message;
  err.status = 400;
  err.code = "E_CODE_INVALID";
  return err;
}

/**
 * @returns {AuthError}
 */
function ENHANCE_YOUR_CALM() {
  let err = new Error("You're doing that too much.");
  err.message = err.message;
  err.status = 420;
  err.code = "E_ENHANCE_YOUR_CALM";
  return err;
}

/**
 * @returns {AuthError}
 */
function INVALID_SESSION() {
  let err = new Error(
    "Missing or invalid cookie session. Please logout and login again."
  );
  err.message = err.message;
  err.status = 400;
  err.code = "E_INVALID_SESSION";
  return err;
}

/**
 * @returns {AuthError}
 */
function SUSPICIOUS_REQUEST() {
  let err = new Error(
    "Something suspicious is going on - as if there are 3 different browsers trying to complete this process."
  );
  err.message = err.message;
  err.status = 400;
  err.code = "E_SUSPICIOUS_REQUEST";
  return err;
}

/**
 * @returns {AuthError}
 */
function SUSPICIOUS_TOKEN() {
  let err = new Error(
    "Something suspicious is going on - the given OIDC token does not belong to this app."
  );
  err.message = err.message;
  err.status = 400;
  err.code = "E_SUSPICIOUS_TOKEN";
  return err;
}

// Likely Developer Mistakes

/**
 * @returns {AuthError}
 */
function DEVELOPER_ERROR(details) {
  let msg = "Oops! One of the programmers made a mistake. It's not your fault.";
  if (details) {
    msg = `${msg} \n\nPlease give the following details to the support team: \n\n${details}`;
  }
  let err = new Error(msg);
  err.message = err.message;
  err.status = 422;
  err.code = "E_DEVELOPER";
  err.details = details;
  return err;
}

/**
 * @returns {AuthError}
 */
function WRONG_TOKEN_TYPE(details) {
  let err = DEVELOPER_ERROR(
    details || "the HTTP Authorization was not given in a supported format"
  );
  return err;
}

/**
 * @returns {AuthError}
 */
function MISSING_TOKEN() {
  let err = DEVELOPER_ERROR(
    "the required authorization token was not provided"
  );
  err.status = 401;
  return err;
}

module.exports = {
  // User
  UNVERIFIED_OIDC_IDENTIFIER,
  CODE_RETRY,
  // Ambi
  CODE_INVALID,
  ENHANCE_YOUR_CALM,
  SUSPICIOUS_REQUEST,
  SUSPICIOUS_TOKEN,
  INVALID_SESSION,
  // Dev
  DEVELOPER_ERROR,
  WRONG_TOKEN_TYPE,
  MISSING_TOKEN,
};

// for README
if (require.main === module) {
  console.info("| Name | Status | Message (truncated) |");
  console.info("| ---- | ------ | ------------------- |");
  Object.keys(module.exports).forEach(function (k) {
    let E = module.exports[k];
    let e = E();
    let code = e.code;
    let msg = e.message;
    if ("E_" + k != e.code) {
      code = k;
      msg = e.details || msg;
    }
    console.info(`| ${code} | ${e.status} | ${msg.slice(0, 45)}... |`);
  });
}
