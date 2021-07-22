"use strict";

let Keyfetch = require("keyfetch");
let E = require("../lib/errors.js");

module.exports = function authMiddleware({
  pub,
  iss,
  optional = false,
  userParam = "user",
  jwsParam = "jws",
}) {
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
      .then(function (jws) {
        req[jwsParam] = jws;
        if (userParam) {
          req[userParam] = req[jwsParam].claims;
        }
        next();
      })
      .catch(function (err) {
        let err2 = E.INVALID_TOKEN();
        err2._original = err;
        next(err);
      });
  };
};
