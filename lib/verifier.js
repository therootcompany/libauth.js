"use strict";

let crypto = require("crypto");

let E = require("./errors.js");
let rnd = require("./rnd.js");
let parseDuration = require("./parse-duration.js");

/**
 * @typedef MagicIdentifier
 * @property {String} [issuer]
 * @property {String} [type]
 * @property {String} [value]
 */

/**
 * @typedef MagicRequest
 * @property {MagicIdentifier} identifier
 * @property {any} state
 */

/**
 * @typedef MagicDevice
 * @property {String} ip
 * @property {String} userAgent
 */

/**
 * @typedef MagicParams
 * @property {String} id
 * @property {String} [code]
 * @property {String} [receipt]
 * @property {Boolean} [finalize]
 * @property {MagicRequest} [request]
 * @property {MagicDevice} device
 */

/**
 * @typedef MagicOrder
 * @property {String} [id]
 * @property {String} [receipt]
 * @property {MagicIdentifier} [identifier]
 * @property {any} [state]
 * @property {Number} [attempts]
 * @property {String} [duration]
 * @property {String} [expires_at]
 * @property {String} [canceled_at]
 * @property {String} [canceled_by]
 * @property {String} [canceled_ip]
 * @property {String} [ordered_at]
 * @property {String} [ordered_by]
 * @property {String} [ordered_ip]
 * @property {String} [verified_at]
 * @property {String} [verified_by]
 * @property {String} [verified_ip]
 */

/**
 * @typedef MagicStatus
 * @property {String} id
 * @property {String} status
 * @property {any} [state]
 * @property {String} [duration]
 * @property {String} [expires_at]
 * @property {String} [canceled_at]
 * @property {String} [canceled_by]
 * @property {String} [ordered_at]
 * @property {String} [ordered_by]
 * @property {String} [verified_at]
 * @property {String} [verified_by]
 */

/**
 * @typedef MagicResponse
 * @property {String} id
 * @property {String} code
 * @property {String} receipt
 * @property {MagicOrder} order
 * @property {MagicStatus} status
 */

// TODO
// x@property {String} [receipt]
// x@property {MagicIdentifier} [identifier]
// x@property {Number} [attempts]
// x@property {String} [canceled_ip]
// x@property {String} [ordered_ip]
// x@property {String} [verified_ip]

/**
 * @typedef challenge
 * @property {string} [id]
 * @property {string} [receipt]
 * @property {string} [code]
 * @property {Object} [identifier]
 * @property {String} [identifier.issuer]
 * @property {String} [identifier.type]
 * @property {String} [identifier.value]
 * @property {string|Object} [state]
 * @property {number} [attempts]
 * @property {string} [duration]
 * @property {string} [expires_at]
 * @property {string} [canceled_at]
 * @property {string} [canceled_by]
 * @property {string} [canceled_ip]
 * @property {string} [ordered_at]
 * @property {string} [ordered_by]
 * @property {string} [ordered_ip]
 */

var C = module.exports;

/**
 * @param {String} issuer
 * @param {String} secret
 * @param {any} _pluginOpts - TODO
 */
C.create = function (issuer, secret, _pluginOpts) {
  let defaultOpts = {
    // optional
    coolDownMs: 250,
    idByteCount: 4,
    /** @type {import('crypto').BinaryToTextEncoding} */
    idEncoding: "base64",
    duration: "24h",
    maxAge: "", // deprecated
    // TODO rename to retries?
    maxAttempts: 5,
    receiptByteCount: 16,
    /** @type {import('crypto').BinaryToTextEncoding} */
    receiptEncoding: "base64",
  };

  let pluginOpts = Object.assign({}, defaultOpts, _pluginOpts || {});
  if (!pluginOpts.store) {
    console.warn(
      "[libauth] Warn: no 'store' given, falling back to in-memory (single-system only) store",
    );
    //@ts-ignore
    pluginOpts.store = require("./memory-store.js");
  }

  // TODO document: 300s, 5m, 12h, 30d
  if (!pluginOpts.duration && pluginOpts.maxAge) {
    pluginOpts.duration = pluginOpts.maxAge;
  }
  let durationMs = parseDuration(pluginOpts.duration);
  let HMAC_SECRET = secret;

  let MagicLink = {};

  /**
   * @param {MagicDevice} device
   * @param {MagicRequest} request
   * @returns {MagicResponse}
   */
  MagicLink.create = function (device, request) {
    if (!request?.identifier?.value) {
      throw E.DEVELOPER_ERROR(
        "'value' (the email/phone/contact) is missing from the request body",
      );
    }

    // Security: HMAC_SECRET MUST be at least 12 bytes (96-bits).
    //
    // With that assumed, we can drop the number of required bits
    // for the code down in the range of 29~32 bits,possibly lower
    // if the number of attempts is capped below 10, and/or the time
    // window is shrunk from 20 minutes to 10m or 5m
    //
    // https://therootcompany.com/blog/how-many-bits-of-entropy-per-character/
    let { code, receipt, id } = MagicLink._rndCode(4, "hex");

    let d = new Date();
    let expiration = new Date(d.valueOf() + parseDuration(pluginOpts.duration));

    /** @type MagicOrder */
    let order = {
      id: id,
      receipt: receipt, //
      state: request.state,
      identifier: request.identifier,
      attempts: 0,
      expires_at: expiration.toISOString(), //
      duration: pluginOpts.duration,
      ordered_at: d.toISOString(),
      ordered_by: device.userAgent,
      ordered_ip: device.ip,
    };

    return {
      id,
      receipt,
      code,
      order,
      //@ts-ignore - TODO
      status: C._toStatus(order),
    };
  };

  /** @type {Object.<string, boolean>} */
  let attempts = {};

  /**
   * Handles the mutex-y bits of the attempt counter / cool-off-er
   * @param {MagicParams} params
   * @param {MagicOrder} order
   * @returns {Promise<challenge>}
   */
  MagicLink.check = async function (params, order) {
    if (params.code) {
      await MagicLink._check(params.id, order, params.code, {
        noDoubleRedeem: true,
        noDoubleExchange: true,
      });
    } else {
      // we can still check after redemption
      MagicLink._assertIsFresh(order, {
        noDoubleRedeem: false,
        noDoubleExchange: true,
        failedValidation: false,
      });
    }

    return order;
  };

  /**
   * Increment on failure, mark verified (redeem) on success.
   * @param {MagicOrder} order
   * @param {String} code
   * @param {MagicDevice} device
   */
  MagicLink.redeem = async function (order, code, device, finalize) {
    await MagicLink._check(order, code, {
      noDoubleRedeem: true,
      noDoubleExchange: false,
    });

    order.verified_at = new Date().toISOString();
    order.verified_by = device.userAgent;
    order.verified_ip = device.ip;

    if (finalize) {
      order.exchanged_at = order.verified_at;
      order.exchanged_by = "";
      order.exchanged_ip = "";
    }

    // TODO save
    return order;
  };

  /**
   * @param {string} id
   * @param {string} receipt
   * @param {import('express').Request} req
   * @returns {Promise<challenge>}
   */
  MagicLink.exchange = async function (id, receipt, req) {
    if (!id || !receipt) {
      throw E.DEVELOPER_ERROR(
        "'id' and/or 'receipt' is missing from the request body",
      );
    }

    let c = await MagicLink.get(id);

    if (!c.verified_at) {
      // TODO better message and error code
      throw E.DEVELOPER_ERROR(
        "a challenge code exchange was requested before the challenge code was submitted",
      );
    }
    MagicLink._assertIsFresh(c, {
      noDoubleRedeem: false,
      noDoubleExchange: true,
      failedValidation: false,
    });

    let exchanged_by = req.headers["user-agent"];
    // TODO ip address should consider 'trust proxy', 'x-forwarded-for', etc
    // It's probably more likely that the WiFi might change than that
    // an attacker has the same token at a different IP address
    //let exchanged_ip = req.ip;
    if (c.ordered_by !== exchanged_by /*|| c.ordered_ip !== exchanged_ip*/) {
      throw E.SUSPICIOUS_REQUEST();
    }

    c.exchanged_at = new Date().toISOString();
    // TODO audit log
    await MagicLink.set(id, c);

    return c;
  };

  /**
   * @param {string} id
   * @param {import('express').Request} req
   * @returns {Promise<challenge>}
   */
  MagicLink.cancel = async function (id, req) {
    let c = await MagicLink.get(id);
    // the code isn't valid, but it's not invalid either - we don't need it
    MagicLink._assertIsFresh(c, {
      noDoubleRedeem: true,
      noDoubleExchange: true,
      failedValidation: false,
    });

    c.canceled_at = new Date().toISOString();
    c.canceled_by = req.headers["user-agent"];
    c.canceled_ip = req.ip;

    await pluginOpts.store.set(id, c);
    //await MagicLink.set(id, c);

    return c;
  };

  /**
   * Handles the mutex-y bits of the attempt counter / cool-off-er
   * @param {MagicOrder} order
   * @param {String} code
   * @param {AssertOpts} assertOpts
   */
  MagicLink._check = async function (order, code, assertOpts) {
    // An attacker could grant himself hundreds or thousands of extra attempts
    // by firing off many requests in parallel - the database might read
    // `attempts = 0` 1000 times and then write `attempts = 1` 1000 times, and
    // then repeat for `attempts = 1`, etc.
    //
    // To prevent this disallow parallel requests.
    // (note: a scalable server system will need a more sophisticated approach)
    if (attempts[order.id]) {
      await C._sleep(pluginOpts.coolDownMs);
      throw E.ENHANCE_YOUR_CALM();
    }

    attempts[order.id] = true;
    let err = await MagicLink._incrementOnFailure(
      order,
      code,
      assertOpts,
    ).catch(Object);

    // always delete the attempt
    delete attempts[order.id];
    if (err) {
      throw err;
    }

    return order;
  };

  /**
   * Increments `attempts` on failure.
   * @param {challenge} order
   * @param {String} code
   * @param {AssertOpts} assertOpts
   */
  MagicLink._incrementOnFailure = async function (order, code, assertOpts) {
    if (!code) {
      throw E.DEVELOPER_ERROR("'code' is missing from the request parameters");
    }

    let pass = C._codesMatch(
      HMAC_SECRET,
      order.receipt || "",
      code,
      pluginOpts.receiptByteCount,
      pluginOpts.receiptEncoding,
    );
    assertOpts.failedValidation = true === pass;
    MagicLink._assertIsFresh(order, assertOpts);
    if (pass) {
      return;
    }

    // tracking attempts is the sole reason for using an ID
    // rather than just the receipt and secret verification code
    if (!order.attempts) {
      order.attempts = 0;
    }
    order.attempts += 1;
    await pluginOpts.store.set(order.id, order);
    throw E.CODE_RETRY();
  };

  /**
   * @param {any} c
   * @param {AssertOpts} assertOpts
   * @returns {Boolean}
   * @throws {Error}
   */
  // TODO c should maintain durationMs, etc
  MagicLink._assertIsFresh = function (c, assertOpts) {
    return C.__assertIsFresh(c, durationMs, pluginOpts.maxAttempts, assertOpts);
  };

  /**
   * @param {number} bytes
   * @param {BufferEncoding} enc
   */
  MagicLink._rndCode = function (bytes, enc) {
    let code = rnd(bytes, enc);
    let receipt = C._hashify(
      HMAC_SECRET,
      code,
      pluginOpts.receiptByteCount,
      pluginOpts.receiptEncoding,
    );
    let id = C._hashify(
      HMAC_SECRET,
      receipt,
      pluginOpts.idByteCount,
      pluginOpts.idEncoding,
    );

    return { code, receipt, id };
  };

  return MagicLink;
};

C._sleep = async function sleep(n = 0) {
  return await new Promise(function (resolve) {
    setTimeout(resolve, n);
  });
};

/**
 * @param {string} HMAC_SECRET
 * @param {string} receipt
 * @param {string} userCode
 * @param {number} bytes
 * @param {string} enc
 */
C._codesMatch = function (HMAC_SECRET, receipt, userCode, bytes, enc) {
  let a = receipt;
  let b = C._hashify(HMAC_SECRET, userCode, bytes, enc);

  if (!a || !b || String(a).length !== String(b).length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
};

/**
 * @param {string} HMAC_SECRET
 * @param {string} code
 * @param {number} bytes
 * @param {string} enc
 * @param {import('crypto').BinaryToTextEncoding} enc
 */
C._hashify = function (HMAC_SECRET, code, bytes, enc) {
  if (!code) {
    // Just a non-false-y string that can't be base64
    return "[BAD SECRET -- DOESN'T EXIST]";
  }

  // How many bits of entropy will be how many encoded characters?
  // See https://therootcompany.com/blog/how-many-bits-of-entropy-per-character/
  let ratio = 2;
  if (!bytes) {
    bytes = 16; // 128-bits
  }
  if (!enc) {
    enc = "base64";
  }
  if ("base64" === enc) {
    ratio = 4 / 3;
  }
  return (
    crypto
      .createHash("sha256")
      .update(Buffer.from(`${HMAC_SECRET}:${code}`, "utf8"))
      //@ts-ignore
      .digest(enc)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "")
      // base64 to byte conversion
      .slice(0, Math.ceil(bytes * ratio))
  );
};

/**
 * @typedef AssertOpts
 * @property {Boolean} noDoubleRedeem
 * @property {Boolean} noDoubleExchange
 * @property {Boolean} [failedValidation]
 */

/**
 * @param {Challenge} c
 * @param {Number} durationMs
 * @param {Number} maxAttempts
 * @param {AssertOpts} opts
 */
C.__assertIsFresh = function (
  c,
  durationMs,
  maxAttempts,
  { noDoubleRedeem = true, noDoubleExchange = true, failedValidation = true },
) {
  if (c.attempts >= maxAttempts) {
    throw E.CODE_INVALID("tried too many times", failedValidation);
  }
  if (noDoubleRedeem) {
    // Note: E.CODE_REDEEMED means all other checks passed
    if (c.verified_at) {
      throw E.CODE_REDEEMED(failedValidation);
    }
  }
  if (noDoubleExchange) {
    // Note: E.CODE_REDEEMED means all other checks passed
    if (c.exchanged_at) {
      throw E.CODE_REDEEMED(failedValidation);
    }
  }
  if (c.canceled_at) {
    throw E.CODE_INVALID("canceled", failedValidation);
  }
  if (c.deleted_at) {
    throw E.CODE_INVALID("deleted", failedValidation);
  }

  let now = Date.now();
  let d = new Date(c.ordered_at).valueOf();
  let fresh = now - d < durationMs;
  if (!fresh) {
    throw E.CODE_INVALID("expired", failedValidation);
  }

  return true;
};

/**
 * @param {Challenge} order
 */
C._toStatus = function (order) {
  let status = "pending";
  if (order.canceled_by) {
    status = "invalid";
  } else if (order.verified_by) {
    status = "valid";
  }

  return {
    id: order.id,
    status: status,
    // TODO always include?
    // receipt: receipt,
    state: order.state,
    duration: order.duration,
    expires_at: order.expires_at,
    ordered_at: order.ordered_at,
    ordered_by: order.ordered_by,
    canceled_at: order.canceled_at,
    canceled_by: order.canceled_by,
    verified_at: order.verified_at,
    verified_by: order.verified_by,
  };
};
