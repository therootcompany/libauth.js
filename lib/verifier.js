"use strict";

let crypto = require("crypto");

let E = require("./errors.js");
let rnd = require("./rnd.js");
let parseDuration = require("./parse-duration.js");

/**
 * @typedef challenge
 * @property {string} id
 * @property {string} [receipt]
 * @property {string} [code]
 * @property {{
 *   type: String,
 *   value: String,
 * }} [identifier]
 * @property {string} [type]
 * @property {string} [value]
 * @property {string|Object} [state]
 * @property {number} [attempts]
 * @property {string} [expires_at]
 * @property {string} [canceled_at]
 * @property {string} [canceled_by]
 * @property {string} [canceled_ip]
 * @property {string} [ordered_at]
 * @property {string} [ordered_by]
 * @property {string} [ordered_ip]
 * @property {string} [iss]
 * @property {string} [duration]
 */

var C = module.exports;

C.create = function (libauth, libOpts, _pluginOpts) {
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
    pluginOpts.store = require("./memory-store.js");
  }

  // TODO document: 300s, 5m, 12h, 30d
  if (!pluginOpts.duration && pluginOpts.maxAge) {
    pluginOpts.duration = pluginOpts.maxAge;
  }
  let durationMs = parseDuration(pluginOpts.duration);
  let HMAC_SECRET = libOpts.secret;

  let MagicLink = {};

  /**
   * @param {{
   *   type: String,
   *   value: String,
   * }} identifier
   * @param {Object} req
   * @param {String} req.ip
   * @param {String} req.userAgent
   * @param {any} req.headers
   * @param {any} req.state
   * @param {any} [req.body]
   * @param {any} opts
   * @returns {challenge}
   */
  MagicLink.create = function (identifier, req, opts = {}) {
    let ua = req?.userAgent || (req?.headers && req.headers["user-agent"]);
    let ip = req?.ip;
    let state = req?.state || req?.body?.state;
    if ("email" === identifier.type) {
      // normalize email
      identifier.value = (identifier.value || "").trim().toLowerCase();
    }

    if (!identifier.value) {
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
    let _duration = opts?.duration || opts?.maxAge || pluginOpts.duration;
    let expiration = new Date(d.valueOf() + parseDuration(_duration));

    // TODO we should pass back one grand representation,
    // pluck the receipt from it, and have the code separate

    /** @type challenge */
    let order = {
      id: id,
      receipt: receipt, //
      state: state,
      identifier: {
        type: identifier.type,
        value: identifier.value,
      },
      type: identifier.type,
      value: identifier.value,
      attempts: 0,
      expires_at: expiration.toISOString(), //
      ordered_at: d.toISOString(),
      ordered_by: ua,
      ordered_ip: ip,
      iss: libOpts.issuer,
      duration: _duration,
    };

    // for the notify handler
    let authnParams = {
      strategy: "challenge",
      code: c.code,
      order: {
        id: c.id,
        state: c.state,
        identifier: {
          type: c.identifier?.type || c.type, // email
          value: c.identifier?.value || c.value, // john.doe@gmail.com
        },
        type: c.type, // email
        value: c.value, // john.doe@gmail.com
        userAgent: c.ordered_by,
        //@ts-ignore
        issuer: opts?.iss || libOpts.issuer,
        //@ts-ignore
        iss: opts?.iss || libOpts.issuer,
        // for the client
      },
      receipt: {
        id: c.id,
        duration: c.duration,
        receipt: c.receipt,
        expires_at: c.expires_at,
      },
    };

    return {
      order: order,
      code: code,
    };
  };

  /**
   * Sanitizes and returns challenge object
   * @param {string} id
   */
  MagicLink.get = async function (id) {
    let c = await pluginOpts.store.get(id);
    if (!c) {
      throw E.CODE_NOT_FOUND();
    }
    Object.keys(c).forEach(function (k) {
      if ("_" === k[0]) {
        c[k] = undefined;
      }
    });
    return c;
  };

  /**
   * Will sanitize and save the challenge object
   * @param {string} id
   * @param {any} c
   */
  MagicLink.set = async function (id, c) {
    c = Object.assign({}, c);
    if ("undefined" !== typeof c.code) {
      c.code = undefined;
    }
    Object.keys(c).forEach(function (k) {
      if ("_" === k[0] && "undefined" !== typeof c[k]) {
        c[k] = undefined;
      }
    });
    await pluginOpts.store.set(id, c);
  };

  /** @type {Object.<string, boolean>} */
  let attempts = {};

  /**
   * Handles the mutex-y bits of the attempt counter / cool-off-er
   * @param {string} id
   * @param {string} [code]
   * @param {import('express').Request} [req]
   * @returns {Promise<challenge>}
   */
  MagicLink.check = async function (id, code = "", req = undefined) {
    if (!id) {
      throw E.DEVELOPER_ERROR("'id' is missing from the query parameters");
    }

    let c = await MagicLink.get(id);

    if (code) {
      await MagicLink._check(id, c, code, {
        noDoubleRedeem: true,
        noDoubleExchange: true,
      });
    } else {
      // we can still check after redemption
      MagicLink._assertIsFresh(c, {
        noDoubleRedeem: false,
        noDoubleExchange: true,
        failedValidation: false,
      });
    }

    return c;
  };

  /**
   * Increment on failure, mark verified (redeem) on success.
   * @param {string} id
   * @param {string} code
   * @param {import('express').Request} req
   */
  MagicLink.redeem = async function (id, code, req) {
    let finalize = req.body.finalize;
    let c = await MagicLink.get(id);

    await MagicLink._check(id, c, code, {
      noDoubleRedeem: true,
      noDoubleExchange: false,
    });

    c.verified_at = new Date().toISOString();
    c.verified_by = req.headers["user-agent"];
    c.verified_ip = req.ip;

    if (finalize) {
      c.exchanged_at = new Date().toISOString();
      c.exchanged_by = "";
      c.exchanged_ip = "";
    }
    await pluginOpts.store.set(id, c);

    return c;
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
   * @param {string} id
   * @param {challenge} c
   * @param {string} code
   * @param {AssertOpts} assertOpts
   */
  MagicLink._check = async function (id, c, code, assertOpts) {
    // An attacker could grant himself hundreds or thousands of extra attempts
    // by firing off many requests in parallel - the database might read
    // `attempts = 0` 1000 times and then write `attempts = 1` 1000 times, and
    // then repeat for `attempts = 1`, etc.
    //
    // To prevent this disallow parallel requests.
    // (note: a scalable server system will need a more sophisticated approach)
    if (attempts[id]) {
      await C._sleep(pluginOpts.coolDownMs);
      throw E.ENHANCE_YOUR_CALM();
    }

    attempts[id] = true;
    let err = await MagicLink._incrementOnFailure(c, code, assertOpts).catch(
      Object,
    );

    // always delete the attempt
    delete attempts[id];
    if (err) {
      throw err;
    }

    return c;
  };

  /**
   * Increments `attempts` on failure.
   * @param {challenge} c
   * @param {String} code
   * @param {AssertOpts} assertOpts
   */
  MagicLink._incrementOnFailure = async function (c, code, assertOpts) {
    if (!code) {
      throw E.DEVELOPER_ERROR("'code' is missing from the request parameters");
    }

    let pass = C._codesMatch(
      HMAC_SECRET,
      c.receipt || "",
      code,
      pluginOpts.receiptByteCount,
      pluginOpts.receiptEncoding,
    );
    assertOpts.failedValidation = true === pass;
    MagicLink._assertIsFresh(c, assertOpts);
    if (pass) {
      return;
    }

    // tracking attempts is the sole reason for using an ID
    // rather than just the receipt and secret verification code
    if (!c.attempts) {
      c.attempts = 0;
    }
    c.attempts += 1;
    await pluginOpts.store.set(c.id, c);
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
