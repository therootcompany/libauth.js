"use strict";

// TODO add types to keyfetch
//@ts-ignore
let Keyfetch = require("keyfetch");
let E = require("../lib/errors.js");

/*
 * @typedef {Object} VerifyOpts
 * @property {any} [pub]
 * @property {string} iss
 * @property {boolean} [optional]
 * @property {string} [userParam]
 * @property {string} [jwsParam]
 */

/*
 * @param {VerifyOpts}
 * @returns {import('express').Handler}
 */

/**
 * @param {{
 *   pub?: any,
 *   iss: string,
 *   optional?: boolean,
 *   userParam?: string,
 *   jwsParam?: string,
 * }} opts
 * @returns {import('express').Handler}
 */
function authMiddleware({
  pub,
  iss,
  optional = false,
  userParam = "user",
  jwsParam = "jws",
}) {
  /** @type {import('express').Handler} */
  return async function (req, res, next) {
    let parts = (req.headers.authorization || "").split(" ");
    let jwt = parts[1];
    if (!jwt) {
      if (optional) {
        next();
        return;
      }

      next(E.MISSING_TOKEN());
      return;
    }

    if ("Bearer" !== parts[0] || parts[2]) {
      next(E.WRONG_TOKEN_TYPE());
      return;
    }

    await Keyfetch.jwt
      .verify(jwt, {
        jwk: pub,
        issuers: [iss],
      })
      .then(
        /** @param {any} jws */
        function (jws) {
          //@ts-ignore
          req[jwsParam] = jws;
          if (userParam) {
            //@ts-ignore
            req[userParam] = req[jwsParam].claims;
          }
          next();
        }
      )
      .catch(
        /** @param {Error} err */
        function (err) {
          //let err2 = E.INVALID_TOKEN();
          //err2._original = err;
          next(err);
        }
      );
  };
}

module.exports = authMiddleware;
