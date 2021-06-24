"use strict";

let Keyfetch = require("keyfetch");
let E = require('./errors.js');

module.exports = function authMiddleware({ pub, iss, optional = false }) {
  return async function (req, res, next) {
    let jwt = (req.headers.authorization || "").replace("Bearer ", "");
    if (!jwt) {
      if (optional) {
        next();
        return;
      }

      next(E.MISSING_TOKEN());
      return;
    }

    req.jws = await Keyfetch.jwt.verify(jwt, { jwk: pub, issuers: [iss] });
    next();
  };
};
