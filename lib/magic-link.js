"use strict";

let crypto = require("crypto");

let Keypairs = require("keypairs");
let rnd = require("./rnd.js");
let localhosts = ["::ffff:127.0.0.1", "127.0.0.1", "::1"];

module.exports = function ({
  _keypair,
  notify,
  store,
  iss,
  DEVELOPMENT,
  _getIdClaims,
  _getAccessClaims,
  _verifyJwt,
  _grantTokenAndCookie,
}) {
  let app = require("@root/async-router").Router();

  // TODO turn into option that gets passed
  let mlExpiryAge = 15 * 60 * 1000;

  function secretToId(secret) {
    return (
      crypto
        .createHash("sha256")
        .update(Buffer.from(secret, "base64"))
        // TODO double check that bit-entropy conversion on base64 is 0.75
        // 16 bytes = 128 bits = 22 base64 chars
        .digest("base64")
        .slice(0, 22)
    );
  }

  // Email Verification Challenges
  // TODO cleanup / rename
  app.post("/api/authn/challenge/issue", async function (req, res) {
    let secret = rnd(16, "base64");
    let id = secretToId(secret);
    let ua = req.headers["user-agent"];
    let claims = {
      challenge_id: id,
      type: req.body.type,
      value: req.body.value,
      // TODO ip address
    };
    await store.set(
      id,
      Object.assign({}, claims, {
        secret: secret,
        ordered_at: new Date().toISOString(),
        ordered_by: ua,
        // TODO ip address should consider 'trust proxy', 'x-forwarded-for', etc
        issued_ip: res.socket.remoteAddress,
      })
    );

    if (!DEVELOPMENT) {
      await notify({
        // TODO let front-end suggest template type
        template: "issue",
        type: claims.type, // email
        value: claims.value, // john.doe@gmail.com
        ua: ua,
        // TODO: nomenclature
        // https://example.com/#login?token=xxxxxx
        challenge_url: iss + "/#login?token=" + secret,
        secret: secret,
        //challenge_redirect: iss + '/login/?token='
      });
    }

    // TODO accept _signJwt and nix use of _keypair
    let jwt = await Keypairs.signJwt({
      jwk: _keypair.keypair.private,
      iss: iss,
      exp: "1h",
      // optional claims
      claims: claims,
    });
    let result = { success: true, challenge_token: jwt };
    if (DEVELOPMENT) {
      if (
        localhosts.includes(req.socket.remoteAddress) &&
        (!req.ip || localhosts.includes(req.ip))
      ) {
        console.warn(
          "[Warn] SECURITY: giving out the challenge secret to localhost in dev mode"
        );
        result.secret = secret;
      }
    }
    res.json(result);
  });

  function mlIsFresh(at) {
    let now = Date.now();
    let d = new Date(at).valueOf();
    return now - d < mlExpiryAge;
  }

  app.get("/api/authn/challenge", async function (req, res) {
    let secret = req.query.token;
    let challenge_token = req.query.challenge_token;
    let meta;
    if (secret) {
      let id = secretToId(secret);
      meta = await store.get(id);
    } else if (challenge_token) {
      let jws = await _verifyJwt(challenge_token).catch(function (err) {
        err.status = 400;
        throw err;
      });
      let id = jws.claims.challenge_id;
      meta = await store.get(id);
    }

    if (!meta || !mlIsFresh(meta.ordered_at)) {
      let err = new Error(
        "the given email verification token does not exist or is expired"
      );
      err.status = 400;
      err.code = "INVALID_TOKEN";
      throw err;
    }
    res.json({
      success: true,
      ordered_at: meta.ordered_at,
      ordered_by: meta.ordered_by,
      verified_at: meta.verified_at,
      verified_by: meta.verified_by,
    });
  });

  app.post("/api/authn/challenge/complete", async function (req, res) {
    // TODO option for how long to remember device
    // (globally/server, and locally/browser)
    let secret = req.body.token || req.query.token;
    let id = secretToId(secret);
    let meta = await store.get(id);
    if (!meta || !mlIsFresh(meta.ordered_at)) {
      let err = new Error(
        "the given email verification token does not exist or is expired"
      );
      err.status = 400;
      err.code = "INVALID_TOKEN";
      throw err;
    }

    meta.verified_at = new Date().toISOString();
    meta.verified_by = req.headers["user-agent"];
    // TODO ip address should consider 'trust proxy', 'x-forwarded-for', etc
    meta.verified_ip = res.socket.remoteAddress;
    // TODO option to expire challenge_token / exchange
    await store.set(id, meta);

    // TODO respect meta.type (such as 'tel')
    let claims = await _getIdClaims({
      email: meta.value,
      iss: iss,
    });
    console.log("[DEBUG]", claims);

    // TODO a way to pass longevity of cookie and token
    let { id_token, access_token } = await _grantTokenAndCookie(claims, res);

    res.json({
      success: true,
      status: "valid",
      id_token: id_token,
      access_token: access_token,
    });
  });

  app.post("/api/authn/challenge/exchange", async function (req, res) {
    let exchange = req.body.challenge_token;
    let jws = await _verifyJwt(exchange);
    let id = jws.claims.challenge_id;
    let meta = await store.get(id);
    if (!meta || !mlIsFresh(meta.ordered_at)) {
      let err = new Error(
        "The given email verification token does not exist or is expired."
      );
      err.status = 400;
      err.code = "INVALID_TOKEN";
      throw err;
    }

    if (!meta.verified_at) {
      // TODO better message and error code
      let err = new Error(
        "The magic link has not been clicked. This is a programmer error. The person who coded this should have checked that first."
      );
      err.status = 400;
      err.code = "INVALID_TOKEN";
      throw err;
    }

    meta.exchanged_at = new Date().toISOString();
    let exchanged_by = req.headers["user-agent"];
    if (meta.ordered_by !== exchanged_by) {
      let err = new Error(
        "It looks like something suspicious is going on - as if you there are 3 different browsers trying to complete this process."
      );
      err.status = 400;
      err.code = "SUSPICIOUS_REQUEST";
      throw err;
    }

    // TODO ip address should consider 'trust proxy', 'x-forwarded-for', etc
    meta.exchanged_ip = res.socket.remoteAddress;
    await store.set(id, meta);

    let claims = await _getIdClaims({
      // TODO respect meta.type (such as 'tel')
      email: meta.value,
      iss: iss,
    });

    // TODO a way to pass longevity of cookie and token
    let { id_token, access_token } = await _grantTokenAndCookie(claims, res);

    res.json({
      success: true,
      status: "valid",
      id_token: id_token,
      access_token: access_token,
    });
  });

  return app;
};
