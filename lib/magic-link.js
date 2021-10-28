"use strict";

let crypto = require("crypto");

let E = require("./errors.js");

let localhosts = ["::ffff:127.0.0.1", "127.0.0.1", "::1"];

let Challenger = module.exports;

/**
 * @param {any} opts
 * //@returns {Object<import('express').Handler>}
 */
Challenger.createRouter = function (opts) {
  if (!opts.verifier) {
    opts.verifier = require("./verifier.js").create(opts);
  }
  let routes = Challenger._createRoutes(opts);
  return routes;
};

Challenger._createRoutes = function ({
  //@ts-ignore
  verifier,
  DEVELOPMENT = false,
  _developmentSendSecretVerificationCode = false,

  authnParam = "authn",
  /** @type {function} */
  //@ts-ignore
  _strategyHandler,
  /** @type {function} */
  //@ts-ignore
  grantTokensAndCookie,
}) {
  let Routes = {};

  //
  // Email Verification Challenges
  //
  /** @type {import('express').Handler} */
  Routes.orderVerification = async function (req, res) {
    // TODO return Promise.resolve().then(doThisRoute).catch(next);
    let _devSendCode =
      req.body._developmentSendSecretVerificationCode ||
      req.body._development_send_secret_verification_code;

    let identifier = {
      type: req.body?.type || "email",
      value: req.body?.value || req.body?.email || "",
    };
    // arbitrary client state (so that when verification request is sent from
    // desktop and responded to on mobile or vice-versa the client can rehydrate
    // something meaningful)
    let state = req.body?.state;
    if (state && "object" === typeof state) {
      let maxKeys = 20;
      let maxSize = 1024;
      let len = Object.keys(state).length;
      if (len > maxKeys) {
        let err = new Error(
          `'state' has '${len}' keys, but should be limited to '${maxKeys}'`
        );
        //@ts-ignore
        err.code = "BAD_REQUEST";
        //@ts-ignore
        err.status = 400;
        throw err;
      }
      let size = Object.keys(state).reduce(function (n, k) {
        let val = state[k];
        if ("string" !== typeof val) {
          let json = JSON.stringify(val);
          let err = new Error(
            `'state' should only have string values, not '${json}'`
          );
          //@ts-ignore
          err.code = "BAD_REQUEST";
          //@ts-ignore
          err.status = 400;
          throw err;
        }
        return n + k.length + val.length;
      }, 0);
      if (size > maxSize) {
        let err = new Error(
          `'state' should be constrained to ${maxSize} bytes`
        );
        //@ts-ignore
        err.code = "BAD_REQUEST";
        //@ts-ignore
        err.status = 400;
        throw err;
      }
    }

    let opts = {};
    let c = verifier.create(identifier, req, opts);
    // TODO set limits (ex: <=20 keys, string values only, <= 1kb total)
    c.state = state;
    await verifier.notify(c, req, opts);
    // TODO put create in set?
    await verifier.set(c.id, c);

    let result = {
      success: true,
      id: c.id,
      receipt: c.receipt,
      expires_at: c.expires_at,
      /** @type {string|undefined} */
      _development_secret_verification_code: undefined,
    };

    if (DEVELOPMENT) {
      let devSendCode = _devSendCode && _developmentSendSecretVerificationCode;
      let isLocal =
        localhosts.includes(res.socket?.remoteAddress || "") &&
        (!req.ip || localhosts.includes(req.ip));
      if (devSendCode && isLocal) {
        console.warn(
          "[auth3000] SECURITY: giving out the secret verification code to localhost in DEVELOPMENT mode"
        );
        result._development_secret_verification_code = c.code;
      }
    }

    res.json(result);
  };

  /** @type {import('express').Handler} */
  Routes.checkStatus = async function (req, res) {
    let id = req.query.id || req.body.id;
    // increments failure count on bad code,
    // but doesn't consume the code on success
    let code = req.query.code || req.body.code;
    let c = await verifier.check(id, code, req);

    // TODO what should the escape hatch be for
    // taking control of the response?
    /*
    if (escapeHatch) {
      giveBackControl(req, res)
      return;
    }
    */
    res.json({
      success: true,
      id: id,
      status: c.verified_by ? "valid" : "pending",
      state: c.state,
      duration: c.duration,
      ordered_at: c.ordered_at,
      ordered_by: c.ordered_by,
      verified_at: c.verified_at,
      verified_by: c.verified_by,
      expires_at: c.expires_at,
    });
  };

  /** @type {import('express').Handler} */
  Routes.redeemCode = async function (req, res) {
    // TODO needs a finalize that excludes reuse by exchange
    let code =
      req.body.code || req.query.code || req.body.token || req.query.token;
    let id = req.body.id || req.query.id;

    if (!id || !code) {
      throw E.DEVELOPER_ERROR(
        "'id' and/or 'code' is missing from the query parameters and/or request body"
      );
    }

    // increments failure count on bad code
    let c = await verifier.redeem(id, code, req);

    //@ts-ignore
    req[authnParam] = {
      strategy: "challenge",
      _exchange: "redeem",
      _verification: c,
      state: c.state,
      duration: c.duration,
      type: c.type,
      value: c.value,
      email: c.value,
      iss: c.iss,
      userAgent: c.verified_by,
      id,
    };
    let allClaims = await _strategyHandler(req, res);
    //@ts-ignore
    req[authnParam] = null;

    // TODO deprecate, remove
    if (allClaims || !res.headersSent) {
      let { id_token, access_token } = await grantTokensAndCookie(
        allClaims,
        req,
        res
      );

      res.json({
        success: true,
        status: "valid",
        state: c.state,
        id_token: id_token,
        access_token: access_token,
      });
    }
  };

  /** @type {import('express').Handler} */
  Routes.exchangeReceipt = async function (req, res) {
    let id = req.body.id;
    let receipt = req.body.receipt;

    if (!id || !receipt) {
      throw E.DEVELOPER_ERROR(
        "'id' and/or 'receipt' is missing from the request body"
      );
    }

    let c = await verifier.exchange(id, receipt, req);

    //@ts-ignore
    req[authnParam] = {
      strategy: "challenge",
      _exchange: "exchange",
      _verification: c,
      state: c.state,
      duration: c.duration,
      type: c.type,
      value: c.value,
      email: c.value,
      iss: c.iss,
      userAgent: c.exchanged_by,
      id,
    };
    let allClaims = await _strategyHandler(req, res);
    //@ts-ignore
    req[authnParam] = null;

    // TODO deprecate
    if (allClaims || !res.headersSent) {
      let { id_token, access_token } = await grantTokensAndCookie(
        allClaims,
        req,
        res
      );

      res.json({
        success: true,
        status: "valid",
        state: c.state,
        id_token: id_token,
        access_token: access_token,
      });
    }
  };

  return Routes;
};
