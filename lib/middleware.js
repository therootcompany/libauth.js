"use strict";

let Keyfetch = require("keyfetch");

module.exports = function authMiddleware({ pub, iss, strict = false }) {
  return async function (req, res, next) {
    let jwt = (req.headers.authorization || "").replace("Bearer ", "");
    if (!jwt && !strict) {
      next();
      return;
    }

    req.jws = await Keyfetch.jwt.verify(jwt, { jwk: pub, iss: iss });
    next();
  };
};
