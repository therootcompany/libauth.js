"use strict";

let crypto = require("crypto");

let E = require("./errors.js");

module.exports.decodeAuthorizationBasic = decodeAuthorizationBasic;
module.exports.decodeAuthorizationBasicValue = decodeAuthorizationBasicValue;
module.exports.secureCompare = secureCompare;

function decodeAuthorizationBasic(req = "") {
  let basic = req;
  if ("string" !== typeof req) {
    basic = req?.headers?.Authorization || "";
  }

  let parts = req.split(" ");
  if ("Basic" !== parts[0]) {
    throw E.WRONG_TOKEN_TYPE();
  }

  let auth = parts[1] || "";
  return decodeAuthorizationBasicValue(auth);
}

function decodeAuthorizationBasicValue(auth) {
  let parts;
  try {
    parts = Buffer.from(auth, "base64").toString("utf8").split(":");
  } catch (e) {
    throw E.WRONG_TOKEN_TYPE();
  }

  let u = parts[0];
  let p = parts.slice(1).join(":");
  return {
    username: u,
    password: p,
  };
}

function secureCompare(trusted = "", given = "", min = 16) {
  // a safeguard against accidental empty string and NaN comparison
  let longEnough = trusted.length >= min;
  if (!longEnough) {
    return false;
  }

  if (trusted.length !== given.length) {
    return false;
  }

  return crypto.timingSafeEqual(Buffer.from(trusted), Buffer.from(given));
}
