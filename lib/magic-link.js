"use strict";

let crypto = require("crypto");

let E = require("./errors.js");

let localhosts = ["::ffff:127.0.0.1", "127.0.0.1", "::1"];

let Challenger = module.exports;

/**
 * @param {any} opts
 * @returns {import('express').Handler}
 */
Challenger.createRouter = function (opts) {
  let app = require("@root/async-router").Router();

  if (!opts.verifier) {
    opts.verifier = require("./verifier.js").create(opts);
  }
  let routes = Challenger._createRoutes(opts);

  app.post("/order", routes.orderVerification);
  app.get("/status", routes.checkStatus);
  app.get("/", routes.checkStatus);
  app.post("/finalize", routes.finalizeVerification);
  app.post("/exchange", routes.exchangeChallengeToken);

  return app;
};

Challenger._createRoutes = function ({
  //@ts-ignore
  verifier,
  DEVELOPMENT = false,
  _developmentSendSecretVerificationCode = false,

  authnParam = "authn",
  /** @type {function} */
  //@ts-ignore
  _getClaims,
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
    let _devSendCode =
      req.body._developmentSendSecretVerificationCode ||
      req.body._development_send_secret_verification_code;

    let identifier = {
      type: req.body?.type || "email",
      value: req.body?.value || req.body?.email || "",
    };

    let opts = {};
    let c = verifier.create(identifier, req, opts);
    await verifier.notify(c, req, opts);
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
      if (
        (_devSendCode && _developmentSendSecretVerificationCode) ||
        (localhosts.includes(res.socket?.remoteAddress || "") &&
          (!req.ip || localhosts.includes(req.ip)))
      ) {
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
    // increments failure count on bad code
    let code = req.query.code || req.body.code;
    let c = await verifier.check(id, code, req);

    let status = "pending";
    if (c.verified_by) {
      status = "valid";
    } else if (c.canceled_by) {
      status = "invalid";
    }
    res.json({
      success: true,
      id: id,
      status: status,
      ordered_at: c.ordered_at,
      ordered_by: c.ordered_by,
      canceled_at: c.canceled_at,
      canceled_by: c.canceled_by,
      verified_at: c.verified_at,
      verified_by: c.verified_by,
      expires_at: c.expires_at,
    });
  };

  /** @type {import('express').Handler} */
  Routes.finalizeVerification = async function (req, res) {
    let code =
      req.body.code || req.query.code || req.body.token || req.query.token;
    let id = req.body.id || req.query.id;
    let cancel = req.body.cancel || req.query.cancel;

    if (!id || !code) {
      if (!code && !cancel) {
        throw E.DEVELOPER_ERROR(
          "'id' and/or 'code' is missing from the query parameters and/or request body"
        );
      }
    }
    if (cancel) {
      //@ts-ignore
      await Routes.cancel(req, res);
      return;
    }

    // increments failure count on bad code
    let c = await verifier.redeem(id, code, req);

    //@ts-ignore
    req[authnParam] = {
      strategy: "challenge",
      type: c.type,
      value: c.value,
      email: c.value,
      iss: c.iss,
      userAgent: c.verified_by,
      id,
    };
    let allClaims = await _getClaims(req, res);
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
        id_token: id_token,
        access_token: access_token,
      });
    }
  };

  /** @type {import('express').Handler} */
  Routes.cancel = async function (req, res) {
    let id = req.body.id || req.query.id;
    let c = await verifier.cancel(id, req);

    res.json({
      success: true,
      status: "invalid",
      id: id,
      canceled_at: c.canceled_at,
      canceled_by: c.canceled_by,
    });
  };

  /** @type {import('express').Handler} */
  Routes.exchangeChallengeToken = async function (req, res) {
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
      type: c.type,
      value: c.value,
      email: c.value,
      iss: c.iss,
      userAgent: c.exchanged_by,
      id,
    };
    let allClaims = await _getClaims(req, res);
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
        id_token: id_token,
        access_token: access_token,
      });
    }
  };

  return Routes;
};
