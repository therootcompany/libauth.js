"use strict";

let crypto = require("crypto");

let E = require("./errors.js");
let rnd = require("./rnd.js");
let parseDuration = require("./parse-duration.js");

let localhosts = ["::ffff:127.0.0.1", "127.0.0.1", "::1"];

module.exports = function ({
  DEVELOPMENT,
  _developmentSendChallengeSecret,
  HMAC_SECRET,
  notify,
  store,
  iss,
  challengeMaxAge,
  challengeMaxAttempts,
  _authnParam,
  _getClaims,
  _grantTokensAndCookie,
}) {
  let app = require("@root/async-router").Router();

  // TODO document: 300s, 5m, 12h, 30d
  let mlExpiryAge = challengeMaxAge || "20m";
  let mlExpiryMs = parseDuration(mlExpiryAge);
  let mlMaxAttempts = challengeMaxAttempts || 5;
  let mlIdBytes = 4;
  let mlIdEncoding = "base64";
  let mlReceiptBytes = 16;
  let mlReceiptEncoding = "base64";

  function rndSecret(bytes, enc) {
    let secret = rnd(bytes, enc);
    let receipt = secretToId(
      HMAC_SECRET,
      secret,
      mlReceiptBytes,
      mlReceiptEncoding
    );
    let id = secretToId(HMAC_SECRET, receipt, mlIdBytes, mlIdEncoding);
    return { secret, receipt, id };
  }

  function secretToId(HMAC_SECRET, secret, bytes, enc) {
    if (!secret) {
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
        .update(Buffer.from(`${HMAC_SECRET}:${secret}`, "utf8"))
        .digest(enc)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "")
        // base64 to byte conversion
        .slice(0, Math.ceil(bytes * ratio))
    );
  }

  function secretsMatch(a, b) {
    if (!a || !b || String(a).length !== String(b).length) {
      return false;
    }
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  }

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
  let orderVerification = async function (req, res) {
    // if this is empty it's a developer error, not a user error
    let body = req.body || {};

    // Security: HMAC_SECRET MUST be at least 12 bytes (96-bits).
    //
    // With that assumed, we can drop the number of required bits
    // for the secret down in the range of 29~32 bits,possibly lower
    // if the number of attempts is capped below 10, and/or the time
    // window is shrunk from 20 minutes to 10m or 5m
    //
    // https://therootcompany.com/blog/how-many-bits-of-entropy-per-character/
    let { secret, receipt, id } = rndSecret(4, "hex");
    let ua = req.headers["user-agent"];
    let claims = {
      challenge_id: id,
      type: body.type,
      value: body.value,
      // TODO ip address
    };

    // TODO consider built-in redirect
    //challenge_redirect: `${iss}/login/?token=xxxx&redirect=${iss}/login/`
    req[_authnParam] = {
      strategy: "challenge",
      type: body.type, // email
      value: body.value, // john.doe@gmail.com
      userAgent: ua,
      secret,
      id,
      issuer: iss,
      iss: iss,
    };
    await notify(req);
    req[_authnParam] = null;

    await store.set(
      id,
      Object.assign({}, claims, {
        attempts: 0,
        secret: secret,
        ordered_at: new Date().toISOString(),
        ordered_by: ua,
        ordered_ip: req.ip || res.socket.remoteAddress,
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
        (_developmentSendChallengeSecret &&
          body._developmentSendChallengeSecret) ||
        (localhosts.includes(req.socket.remoteAddress) &&
          (!req.ip || localhosts.includes(req.ip)))
      ) {
        console.warn(
          "[Warn] SECURITY: giving out the challenge secret to localhost in dev mode"
        );
        result._development_secret = secret;
      }
    }
    res.json(result);
  };

  let checkStatus = async function (req, res) {
    let secret = req.query.token;
    let receipt = req.query.receipt;
    let meta;
    let id;
    if (secret) {
      receipt = secretToId(
        HMAC_SECRET,
        secret,
        mlReceiptBytes,
        mlReceiptEncoding
      );
      id = secretToId(HMAC_SECRET, receipt, mlIdBytes, mlIdEncoding);
    } else if (receipt) {
      id = secretToId(HMAC_SECRET, receipt, mlIdBytes, mlIdEncoding);
    }

    meta = await store.get(id);
    if (!meta || !mlIsFresh(meta)) {
      throw E.INVALID_CODE();
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

  let finalizeVerification = async function (req, res) {
    let secret = req.body.token || req.query.token;
    let id = req.body.id || req.query.id;

    let meta = await store.get(id);
    if (
      !meta ||
      meta.verified_at ||
      !mlIsFresh(meta) ||
      !secretsMatch(meta.secret, secret)
    ) {
      // this is the sole reason for using an ID
      // rather than just the challenge and secret
      meta.attempts += 1;
      store.set(id, meta);
      throw E.INVALID_CODE();
    }

    meta.verified_at = new Date().toISOString();
    meta.verified_by = req.headers["user-agent"];
    meta.verified_ip = req.ip || res.socket.remoteAddress;
    await store.set(id, meta);

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

  let exchangeChallengeToken = async function (req, res) {
    let receipt = req.body.receipt;
    let id = secretToId(HMAC_SECRET, receipt, mlIdBytes, mlIdEncoding);

    let meta = await store.get(id);
    if (!meta || meta.exchanged_at || !mlIsFresh(meta)) {
      throw E.INVALID_CODE();
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
    //let exchanged_ip = res.socket.remoteAddress;
    if (
      meta.ordered_by !== exchanged_by /*|| meta.ordered_ip !== exchanged_ip*/
    ) {
      throw E.SUSPICIOUS_REQUEST();
    }

    meta.exchanged_at = new Date().toISOString();
    // TODO audit log
    await store.set(id, meta);

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
