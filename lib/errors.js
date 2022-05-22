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
 * @typedef AuthRetryError
 * @property {string} message
 * @property {Boolean} E_CODE_RETRY
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
function CODE_NOT_FOUND() {
  return create(
    "That verification id doesn't exist. It may have been mistyped or the URL may not have been copied completely.",
    {
      status: 404,
      code: "E_NOT_FOUND",
    },
  );
}

/**
 * @returns {AuthError}
 */
function CODE_REDEEMED() {
  return create(
    "That verification code has already been used. You cannot use it again.",
    {
      status: 400,
      code: "E_CODE_REDEEMED",
    },
  );
}

/**
 * @returns {AuthRetryError}
 */
function CODE_RETRY() {
  return create(
    "That verification code isn't correct. It may have been mistyped or the URL may not have been copied completely.",
    {
      E_CODE_RETRY: true,
      status: 400,
      code: "E_CODE_RETRY",
    },
  );
}

/**
 * @returns {AuthError}
 */
function OIDC_UNVERIFIED_IDENTIFIER(type = "identifier") {
  return create(
    `You cannot use the ${type} associated with this account because you haven't completed the verification yet.`,
    {
      status: 400,
      code: "E_OIDC_UNVERIFIED_IDENTIFIER",
    },
  );
}

// Ambi-Errors - could be the result of user or developer error

/**
 * @param {String} [detail]
 * @returns {AuthError}
 */
function CODE_INVALID(detail) {
  let details;
  if (detail) {
    details = [`debug: ${detail}`];
  }

  return create(
    "That verification code isn't valid. It may not exist or be expired, or you may tried too many incorrect codes.",
    {
      status: 400,
      code: "E_CODE_INVALID",
      details: details,
    },
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
function SESSION_INVALID() {
  return create(
    "Missing or invalid cookie session. Please logout and login again.",
    {
      status: 400,
      code: "E_SESSION_INVALID",
    },
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
    },
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
    },
  );
}

// Likely Developer Mistakes

/**
 * @param {any} [details]
 * @returns {AuthError}
 */
function OIDC_BAD_GATEWAY(details) {
  return create("remote server gave a non-OK response", {
    status: 502,
    code: "E_OIDC_BAD_GATEWAY",
    details: details,
  });
}

/**
 * @param {any} [details]
 * @returns {AuthError}
 */
function OIDC_BAD_REDIRECT(details) {
  return create(
    `invalid redirect URL: '${details.finalUrl}' is not child of '${details.trustedUrl}'`,
    {
      status: 500,
      code: "E_OIDC_BAD_REDIRECT",
      details: details,
    },
  );
}

/**
 * @param {any} [details]
 * @returns {AuthError}
 */
function OIDC_BAD_REMOTE(details) {
  return create(
    "could not fetch OpenID Configuration - try inspecting the token and checking 'iss'",
    {
      status: 422,
      code: "E_OIDC_BAD_REMOTE",
      details: details,
    },
  );
}

/**
 * @returns {AuthError}
 */
function OIDC_ERROR() {
  return create("unknown oidc error", {
    status: 422,
    code: "E_OIDC_ERROR",
  });
}

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
    details || "the HTTP Authorization was not given in a supported format",
  );
  return err;
}

/**
 * @returns {AuthError}
 */
function MISSING_TOKEN() {
  let err = DEVELOPER_ERROR(
    "the required authorization token was not provided",
  );
  err.status = 401;
  return err;
}

module.exports = {
  // User
  CODE_NOT_FOUND,
  CODE_REDEEMED,
  CODE_RETRY,
  OIDC_UNVERIFIED_IDENTIFIER,
  // Ambi
  CODE_INVALID,
  ENHANCE_YOUR_CALM,
  SUSPICIOUS_REQUEST,
  SUSPICIOUS_TOKEN,
  SESSION_INVALID,
  OIDC_BAD_GATEWAY,
  OIDC_BAD_REDIRECT,
  OIDC_BAD_REMOTE,
  OIDC_ERROR,
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
