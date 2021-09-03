"use strict";

let crypto = require("crypto");

let E = require("./errors.js");
let rnd = require("./rnd.js");
let parseDuration = require("./parse-duration.js");

let localhosts = ["::ffff:127.0.0.1", "127.0.0.1", "::1"];

async function sleep(n = 0) {
  return await new Promise(function (resolve) {
    setTimeout(resolve, n);
  });
}

/** @param {import('express').Request} req */
async function _notify(req) {}

module.exports = function ({
  DEVELOPMENT = false,
  _developmentSendChallengeSecret = false, // deprecated
  _developmentSendSecretVerificationCode = false,
  HMAC_SECRET = "",
  notify = _notify,
  /** @type {import('./memory-store.js').MemoryStore} */
  //@ts-ignore
  store,
  iss = "",
  challengeMaxAge = "20m",
  challengeMaxAttempts = 5,
  _authnParam = "authn",
  /** @type {function} */
  //@ts-ignore
  _getClaims,
  /** @type {function} */
  //@ts-ignore
  _grantTokensAndCookie,
}) {
  let app = require("@root/async-router").Router();

  // TODO document: 300s, 5m, 12h, 30d
  let mlExpiryAge = challengeMaxAge || "20m";
  let mlExpiryMs = parseDuration(mlExpiryAge);
  let mlMaxAttempts = challengeMaxAttempts || 5;
  let mlIdBytes = 4;
  /** @type {import('crypto').BinaryToTextEncoding} */
  let mlIdEncoding = "base64";
  let mlReceiptBytes = 16;
  /** @type {import('crypto').BinaryToTextEncoding} */
  let mlReceiptEncoding = "base64";

  /**
   * @param {number} bytes
   * @param {BufferEncoding} enc
   */
  function rndCode(bytes, enc) {
    let code = rnd(bytes, enc);
    let receipt = hashify(HMAC_SECRET, code, mlReceiptBytes, mlReceiptEncoding);
    let id = hashify(HMAC_SECRET, receipt, mlIdBytes, mlIdEncoding);
    return { code, receipt, id };
  }

  /**
   * @param {string} HMAC_SECRET
   * @param {string} code
   * @param {number} bytes
   * @param {string} enc
   * @param {import('crypto').BinaryToTextEncoding} enc
   */
  function hashify(HMAC_SECRET, code, bytes, enc) {
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
  }

  /**
   * @param {string} a
   * @param {string} b
   */
  function codesMatch(a, b) {
    if (!a || !b || String(a).length !== String(b).length) {
      return false;
    }
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  }

  /**
   * @param {Challenge} meta
   */
  function mlIsFresh(meta) {
    if (
      meta.deleted_at ||
      meta.exchanged_at ||
      meta.attempts >= mlMaxAttempts
    ) {
      return false;
    }
    let now = Date.now();
    let d = new Date(meta.ordered_at).valueOf();
    return now - d < mlExpiryMs;
  }

  //
  // Email Verification Challenges
  //
  /** @type {import('express').Handler} */
  let orderVerification = async function (req, res) {
    // if this is empty it's a developer error, not a user error
    let body = req.body || {};
    if (!body.type || "email" === body.type) {
      // normalize email
      body.value = (body.value || "").trim().toLowerCase();
    }

    // Security: HMAC_SECRET MUST be at least 12 bytes (96-bits).
    //
    // With that assumed, we can drop the number of required bits
    // for the code down in the range of 29~32 bits,possibly lower
    // if the number of attempts is capped below 10, and/or the time
    // window is shrunk from 20 minutes to 10m or 5m
    //
    // https://therootcompany.com/blog/how-many-bits-of-entropy-per-character/
    let { code, receipt, id } = rndCode(4, "hex");
    let ua = req.headers["user-agent"];
    let claims = {
      challenge_id: id,
      type: body.type,
      value: body.value,
      // TODO ip address
    };

    if (!body.value) {
      throw E.DEVELOPER_ERROR(
        "'value' (the email/phone/contact) is missing from the request body"
      );
    }

    // TODO consider built-in redirect
    //challenge_redirect: `${iss}/login/?id=xxxx&code=yyyy&redirect=${iss}/login/`
    //@ts-ignore
    req[_authnParam] = {
      strategy: "challenge",
      type: body.type, // email
      value: body.value, // john.doe@gmail.com
      userAgent: ua,
      code: code,
      secret: code, // deprecated
      id,
      issuer: iss,
      iss: iss,
    };
    await notify(req);
    //@ts-ignore
    req[_authnParam] = null;

    await store.set(
      id,
      Object.assign({}, claims, {
        attempts: 0,
        code,
        secret: code, // deprecated
        ordered_at: new Date().toISOString(),
        ordered_by: ua,
        ordered_ip: req.ip || res.socket?.remoteAddress,
      })
    );

    let result = {
      success: true,
      id: id,
      receipt: receipt,
      _expiry: mlExpiryAge,
    };
    if (DEVELOPMENT) {
      if (
        (_developmentSendSecretVerificationCode &&
          body._developmentSendSecretVerificationCode) ||
        (_developmentSendChallengeSecret && // deprecated
          body._developmentSendChallengeSecret) ||
        (localhosts.includes(req.socket?.remoteAddress || "") &&
          (!req.ip || localhosts.includes(req.ip)))
      ) {
        console.warn(
          "[auth3000] SECURITY: giving out the secret verification code to localhost in DEVELOPMENT mode"
        );
        //@ts-ignore
        result._development_secret = code; // deprecated
        //@ts-ignore
        result._development_secret_verification_code = code;
      }
    }
    res.json(result);
  };

  /** @type {import('express').Handler} */
  let checkStatus = async function (req, res) {
    let id = req.query.id;
    //let code = req.query.code || req.query.token;
    //let receipt = req.query.receipt;
    let meta;

    if (!id) {
      throw E.DEVELOPER_ERROR("'id' is missing from the query parameters");
    }

    meta = await store.get(id);
    if (!meta || !mlIsFresh(meta)) {
      throw E.CODE_INVALID();
    }

    res.json({
      success: true,
      id: id,
      status: meta.verified_by ? "valid" : "pending",
      ordered_at: meta.ordered_at,
      ordered_by: meta.ordered_by,
      verified_at: meta.verified_at,
      verified_by: meta.verified_by,
    });
  };

  /** @type {Object.<string, boolean>} */
  let attempts = {};
  /** @type {import('express').Handler} */
  let finalizeVerification = async function (req, res) {
    let code =
      req.body.code || req.query.code || req.body.token || req.query.token;
    let id = req.body.id || req.query.id;

    if (!id || !code) {
      throw E.DEVELOPER_ERROR(
        "'id' and/or 'code' is missing from the query parameters and/or request body"
      );
    }

    // An attacker could grant himself hundreds or thousands of extra attempts
    // by firing off many requests in parallel - the database might read
    // `attempts = 0` 1000 times and then write `attempts = 1` 1000 times, and
    // then repeat for `attempts = 1`, etc.
    //
    // To prevent this disallow parallel requests.
    // (note: a scalable server system will need a more sophisticated approach)
    if (attempts[id]) {
      await sleep(250);
      throw E.ENHANCE_YOUR_CALM();
    }
    attempts[id] = true;
    let meta = await _attemptCounter(id, code, req, res).catch(Object);
    delete attempts[id];
    if (meta instanceof Error) {
      throw meta;
    }

    //@ts-ignore
    req[_authnParam] = {
      strategy: "challenge",
      type: meta.type,
      value: meta.value,
      email: meta.value,
      iss: iss,
      userAgent: meta.verified_by,
      id,
    };
    let allClaims = await _getClaims(req);
    //@ts-ignore
    req[_authnParam] = null;

    let { id_token, access_token } = await _grantTokensAndCookie(
      allClaims,
      req,
      res
    );

    res.json({
      success: true,
      status: "valid",
      id_token: id_token,
      access_token: access_token,
    });
  };

  /**
   * @param {string} id
   * @param {string} code
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   */
  async function _attemptCounter(id, code, req, res) {
    let meta = await store.get(id);
    if (!meta || meta.verified_at || !mlIsFresh(meta)) {
      delete attempts[id];
      throw E.CODE_INVALID();
    }

    if (!codesMatch(meta.code, code)) {
      // tracking attempts is the sole reason for using an ID
      // rather than just the receipt and secret verification code
      meta.attempts += 1;
      await store.set(id, meta);
      throw E.CODE_RETRY();
    }

    meta.verified_at = new Date().toISOString();
    meta.verified_by = req.headers["user-agent"];
    meta.verified_ip = req.ip || res.socket?.remoteAddress;
    await store.set(id, meta);

    return meta;
  }

  /** @type {import('express').Handler} */
  let exchangeChallengeToken = async function (req, res) {
    let id = req.body.id;
    let receipt = req.body.receipt;

    if (!id || !receipt) {
      throw E.DEVELOPER_ERROR(
        "'id' and/or 'receipt' is missing from the request body"
      );
    }

    let meta = await store.get(id);
    if (!meta || meta.exchanged_at || !mlIsFresh(meta)) {
      throw E.CODE_INVALID();
    }

    if (!meta.verified_at) {
      // TODO better message and error code
      throw E.DEVELOPER_ERROR(
        "a challenge code exchange was requested before the challenge code was submitted"
      );
    }

    let exchanged_by = req.headers["user-agent"];
    // TODO ip address should consider 'trust proxy', 'x-forwarded-for', etc
    // It's probably more likely that the WiFi might change than that
    // an attacker has the same token at a different IP address
    //let exchanged_ip = req.ip || res.socket.remoteAddress;
    if (
      meta.ordered_by !== exchanged_by /*|| meta.ordered_ip !== exchanged_ip*/
    ) {
      throw E.SUSPICIOUS_REQUEST();
    }

    meta.exchanged_at = new Date().toISOString();
    // TODO audit log
    await store.set(id, meta);

    //@ts-ignore
    req[_authnParam] = {
      strategy: "challenge",
      type: meta.type,
      value: meta.value,
      email: meta.value,
      iss: iss,
      userAgent: meta.exchanged_by,
      id,
    };
    let allClaims = await _getClaims(req);
    //@ts-ignore
    req[_authnParam] = null;

    let { id_token, access_token } = await _grantTokensAndCookie(
      allClaims,
      req,
      res
    );

    res.json({
      success: true,
      status: "valid",
      id_token: id_token,
      access_token: access_token,
    });
  };

  app.post("/order", orderVerification);
  app.get("/status", checkStatus);
  app.get("/", checkStatus);
  app.post("/finalize", finalizeVerification);
  app.post("/exchange", exchangeChallengeToken);

  return app;
};
