"use strict";

let Keyfetch = require("keyfetch");

module.exports = function authMiddleware({ pub, iss, optional = false }) {
  return async function (req, res, next) {
    let jwt = (req.headers.authorization || "").replace("Bearer ", "");
    if (!jwt) {
      if (optional) {
        next();
        return;
      }

      let err = new Error("authorization token required");
      err.code = "INVALID_AUTH";
      next(err);
      return;
    }

    req.jws = await Keyfetch.jwt.verify(jwt, { jwk: pub, issuers: [iss] });
    next();
  };
};
