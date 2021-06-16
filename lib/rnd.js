"use strict";

module.exports = function rnd(len, enc) {
  let crypto = require("crypto");

  return crypto
    .randomBytes(len || 16)
    .toString(enc || "base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
};
