"use strict";

let crypto = require("crypto");

let rnd = require("./rnd.js");
let Util = require("./util.js");

let MagicCode = module.exports;

/**
 * @param {MagicCodeOpts} pluginOpts
 * @returns {MagicCodeGen}
 */
MagicCode.create = function (pluginOpts) {
  let magicCode = {};

  pluginOpts = Object.assign(
    {
      // These are used only for generation
      // (they don't need to persist between restarts)
      codeByteCount: 4,
      codeEncoding: "hex",
      idByteCount: 8,
      idEncoding: "base62",
      // IMPORTANT: used for verification
      // (existing codes become invalid if changed)
      receiptByteCount: 16,
      receiptEncoding: "base62",
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
   * MagicCodeGenerator
   *
   * @param {MagicCodeOpts} opts
   * @returns {Promise<MagicParts>}
   */
  magicCode.generate = async function (opts) {
    let code = rnd(
      opts.codeByteCount || pluginOpts.codeByteCount,
      opts.codeEncoding || pluginOpts.codeEncoding,
    );

    let receipt = magicCode._hashify(
      code,
      opts.receiptByteCount || pluginOpts.receiptByteCount,
      opts.receiptEncoding || pluginOpts.receiptEncoding,
    );

    let id = magicCode._hashify(
      receipt,
      opts.idByteCount || pluginOpts.idByteCount,
      opts.idEncoding || pluginOpts.idEncoding,
    );

    return { code, receipt, id };
  };

  /**
   * @param {MagicOrder} order
   * @param {String} userCode
   * @param {Number} [receiptByteCount]
   * @param {BufferEncoding} [receiptEncoding]
   */
  magicCode._verifyCode = async function (
    order,
    userCode,
    receiptByteCount,
    receiptEncoding,
  ) {
    let knownReceipt = order.receipt || "";
    let userReceipt = magicCode._hashify(
      userCode,
      receiptByteCount || pluginOpts.receiptByteCount,
      receiptEncoding || pluginOpts.receiptEncoding,
    );

    return Util.secureCompare(knownReceipt, userReceipt, receiptByteCount);
  };

  /**
   * @param {MagicOrder} order
   * @param {String} userReceipt
   * @param {Number} [receiptByteCount]
   * @param {BufferEncoding} [receiptEncoding]
   */
  magicCode._verifyReceipt = async function (
    order,
    userReceipt,
    receiptByteCount,
    receiptEncoding,
  ) {
    let knownReceipt = order.receipt || "";

    return Util.secureCompare(knownReceipt, userReceipt, receiptByteCount);
  };

  /**
   * MagicCodeValidator
   *
   * @param {MagicOrder} order
   * @param {MagicParams} params
   * @param {Number} [receiptByteCount]
   * @param {BufferEncoding} [receiptEncoding]
   * @returns {Promise<MagicValidations>}
   */
  magicCode.validate = async function (order, params, opts) {
    /** @type {MagicValidations} */
    let validations = {
      code: null,
      receipt: null,
      valid: false,
    };
    if (params.code) {
      validations.code = await magicCode._verifyCode(
        order,
        params.code,
        opts.receiptByteCount,
        opts.receiptEncoding,
      );
    }
    if (params.receipt) {
      validations.receipt = await magicCode._verifyReceipt(
        order,
        params.receipt,
        opts.receiptByteCount,
        opts.receiptEncoding,
      );
    }

    let failed = false === validations.code || false === validations.receipt;
    let passed = true === validations.code || true === validations.receipt;

    validations.valid = !failed && passed;

    return validations;
  };

  /** TODO
   * @type TextEncoding = 'base64' | 'base64url' | 'base62' | 'base32' | 'hex' | 'decimal'
   */

  /**
   * @param {String} str
   * @param {Number} bytes
   * @param {String} enc
   * @returns {String}
   */
  magicCode._hashify = function (
    str = "",
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

    /** @type {import('crypto').BinaryToTextEncoding} */
    //@ts-ignore
    let encStrict = enc;
    if ("base62" === enc) {
      encStrict = "base64url";
    }

    let result = crypto
      .createHash("sha256")
      .update(Buffer.from(`${MAGIC_SALT}:${str}`, "utf8"))
      .digest(encStrict)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    if ("base62" === enc) {
      result = result
        .replace(/[\+-]+/g, "")
        .replace(/[\/_]/g, "")
        .replace(/=/g, "");
    }

    // base64 to byte conversion
    return result.slice(0, Math.ceil(bytes * ratio));
  };

  return magicCode;
};
