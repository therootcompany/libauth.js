"use strict";

// Possible User Errors

/**
 * @typedef AuthError
 * @property {string} message
 * @property {number} status
 * @property {string} code
 * @property {any} [details]
 */

/**
 * @param {string} msg
 * @param {{
 *   status: number,
 *   code: string,
 *   details?: any,
 * }} opts
 * @returns {AuthError}
 */
function create(msg, { status = 0, code = "", details }) {
  /** @type AuthError */
  //@ts-ignore
  let err = new Error(msg);
  err.message = err.message;
  err.status = status;
  err.code = code;
  if (details) {
    err.details = details;
  }
  return err;
}

/**
 * @returns {AuthError}
 */
function CODE_RETRY() {
  return create(
    "That verification code isn't correct. It may have been mistyped or the URL may not have been copied completely.",
    {
      status: 400,
      code: "E_CODE_RETRY",
    }
  );
}

/**
 * @returns {AuthError}
 */
function UNVERIFIED_OIDC_IDENTIFIER(type = "identifier") {
  return create(
    `You cannot use the ${type} associated with this account because you haven't completed the verification yet.`,
    {
      status: 400,
      code: "E_UNVERIFIED_OIDC_IDENTIFIER",
    }
  );
}

// Ambi-Errors - could be the result of user or developer error

/**
 * @returns {AuthError}
 */
function CODE_INVALID() {
  return create(
    "That verification code isn't valid. It might have been used previously, or might be expired, tried to many times, or just may not exist at all.",
    {
      status: 400,
      code: "E_CODE_INVALID",
    }
  );
}

/**
 * @returns {AuthError}
 */
function ENHANCE_YOUR_CALM() {
  return create("You're doing that too much.", {
    status: 420,
    code: "E_ENHANCE_YOUR_CALM",
  });
}

/**
 * @returns {AuthError}
 */
function INVALID_SESSION() {
  return create(
    "Missing or invalid cookie session. Please logout and login again.",
    {
      status: 400,
      code: "E_INVALID_SESSION",
    }
  );
}

/**
 * @returns {AuthError}
 */
function SUSPICIOUS_REQUEST() {
  return create(
    "Something suspicious is going on - as if there are 3 different browsers trying to complete this process.",
    {
      status: 400,
      code: "E_SUSPICIOUS_REQUEST",
    }
  );
}

/**
 * @returns {AuthError}
 */
function SUSPICIOUS_TOKEN() {
  return create(
    "Something suspicious is going on - the given OIDC token does not belong to this app.",
    {
      status: 400,
      code: "E_SUSPICIOUS_TOKEN",
    }
  );
}

// Likely Developer Mistakes

/**
 * @param {any} [details]
 * @returns {AuthError}
 */
function DEVELOPER_ERROR(details) {
  let msg = "Oops! One of the programmers made a mistake. It's not your fault.";
  if (details) {
    msg = `${msg} \n\nPlease give the following details to the support team: \n\n${details}`;
  }
  return create(msg, {
    status: 422,
    code: "E_DEVELOPER",
    details: details,
  });
}

/**
 * @param {any} [details]
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
    //@ts-ignore
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
