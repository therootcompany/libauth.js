"use strict";

let crypto = require("crypto");

let rnd = require("./rnd.js");
let Util = require("./util.js");

let MagicCode = module.exports;

// TODO codeByteCount -> codeCharLen

/**
 * @param {MagicCodeOpts} pluginOpts
 */
MagicCode.create = function (pluginOpts) {
  let magicCode = {};

  pluginOpts = Object.assign(
    {
      // These are used only for generation
      // (they don't need to persist between restarts)
      codeByteCount: 4,
      codeEncoding: "hex",
      idByteCount: 4,
      idEncoding: "base64",
      // IMPORTANT: used for verification
      // (existing codes become invalid if changed)
      receiptByteCount: 16,
      receiptEncoding: "base64",
      // Security: MAGIC_SALT MUST be at least 12 bytes (96-bits).
      //
      // With that assumed, we can drop the number of required bits
      // for the code down in the range of 29~32 bits,possibly lower
      // if the number of attempts is capped below 10, and/or the time
      // window is shrunk from 20 minutes to 10m or 5m
      //
      // https://therootcompany.com/blog/how-many-bits-of-entropy-per-character/
      magicSalt: "",
    },
    pluginOpts,
  );

  let MAGIC_SALT = pluginOpts.magicSalt;
  if (!pluginOpts.magicSalt) {
    throw new Error("[MagicCode] missing 'opts.magicSalt'");
  }

  /**
   * @param {Number} codeBytes
   * @param {BufferEncoding} codeEnc
   * @param {Number} [idBytes]
   * @param {BufferEncoding} [idEnc]
   * @returns {MagicParts}
   */
  magicCode.generate = function (codeBytes, codeEnc, idBytes, idEnc) {
    let code = rnd(codeBytes, codeEnc);

    let receipt = magicCode._hashify(
      code,
      pluginOpts.receiptByteCount,
      pluginOpts.receiptEncoding,
    );

    let id = magicCode._hashify(
      receipt,
      idBytes || pluginOpts.idByteCount,
      idEnc || pluginOpts.idEncoding,
    );

    return { code, receipt, id };
  };

  /**
   * @param {MagicOrder} order
   * @param {String} code
   * @param {Number} [receiptByteCount]
   * @param {BufferEncoding} [receiptEncoding]
   */
  magicCode.verify = async function (
    order,
    code,
    receiptByteCount,
    receiptEncoding,
  ) {
    let knownReceipt = order.receipt || "";
    let userReceipt = magicCode._hashify(
      code,
      receiptByteCount || pluginOpts.receiptByteCount,
      receiptEncoding || pluginOpts.receiptEncoding,
    );

    return Util.secureCompare(knownReceipt, userReceipt, receiptByteCount);
  };

  /**
   * @param {String} str
   * @param {Number} bytes
   * @param {BufferEncoding} enc
   * @returns {String}
   */
  magicCode._hashify = function (
    str,
    bytes = 16, // 128-bits
    enc = "base64",
  ) {
    if (!str) {
      // Just a non-false-y string that can't be base64
      return "[BAD SECRET -- DOESN'T EXIST]";
    }

    // How many bits of entropy will be how many encoded characters?
    // See https://therootcompany.com/blog/how-many-bits-of-entropy-per-character/
    let ratio = 2;
    if ("base64" === enc) {
      ratio = 4 / 3;
    }

    return (
      crypto
        .createHash("sha256")
        .update(Buffer.from(`${MAGIC_SALT}:${str}`, "utf8"))
        //@ts-ignore
        .digest(enc)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "")
        // base64 to byte conversion
        .slice(0, Math.ceil(bytes * ratio))
    );
  };
};
