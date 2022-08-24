"use strict";

let Crypto = require("crypto");

/**
 * @param {Number} len
 * @param {String} enc
 */
module.exports = function rnd(len = 16, enc = "base62") {
  if ("base62" === enc) {
    // Elongate to account for some number of unusable characters.
    // This will be truncated later.
    len *= 1.5;
    enc = "base64";
  }

  /** @type {import('crypto').BinaryToTextEncoding} */
  //@ts-ignore
  let encStrict = enc;

  let result = Crypto.randomBytes(len)
    .toString(encStrict)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  return result;
};
