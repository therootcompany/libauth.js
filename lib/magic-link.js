"use strict";

let crypto = require("crypto");

let E = require("./errors.js");

let localhosts = ["::ffff:127.0.0.1", "127.0.0.1", "::1"];

let Challenger = module.exports;

/**
 * @param {import('express').Handler} fn
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @returns {Promise<any>}
 */
async function promisifyHandler(fn, req, res) {
  let err = await new Promise(async function (resolve, reject) {
    try {
      //@ts-ignore
      await fn(req, res, resolve).catch(reject);
    } catch (err) {
      reject(err);
    }
  });
  if (err) {
    throw err;
  }
}

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
  iss = "",
  //@ts-ignore
  verifier,
  //@ts-ignore
  notify,
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
          `'state' has '${len}' keys, but should be limited to '${maxKeys}'`,
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
            `'state' should only have string values, not '${json}'`,
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
          `'state' should be constrained to ${maxSize} bytes`,
        );
        //@ts-ignore
        err.code = "BAD_REQUEST";
        //@ts-ignore
        err.status = 400;
        throw err;
      }
    }

    await promisifyHandler(Routes.order, req, res);
    // this req must have req[authnParam] as the notifier info
    await notify(req, {});
    //await verifier.notify(c, req, opts);
    //@ts-ignore
    req[authnParam] = null;

    let result = Object.assign({ success: true }, req.authn.order);

    if (DEVELOPMENT) {
      // TODO return Promise.resolve().then(doThisRoute).catch(next);
      let _devSendCode =
        req.body._developmentSendSecretVerificationCode ||
        req.body._development_send_secret_verification_code;
      let devSendCode = _devSendCode && _developmentSendSecretVerificationCode;
      // the raw connection is local AND the proxied connection is local
      /*
      let isLocal =
        localhosts.includes(res.socket?.remoteAddress || "") &&
        (!req.ip || localhosts.includes(req.ip) || true);
      if (devSendCode && isLocal) {
      */
      console.warn(
        "[auth3000] SECURITY: giving out the secret verification code to localhost in DEVELOPMENT mode",
      );

      result._development_secret_verification_code = req.authn.order.getCode();
      /*
      }
      */
    }

    res.json(result);
  };

  /** @type {import('express').Handler} */
  Routes.order = async function (req, res, next) {
    let ua = req.headers["user-agent"];
    let ip = req.ip;
    let body = req.body || {};

    let state = body?.state;
    let identifier = {
      type: body?.type || "email",
      value: body?.value || body?.email || "",
    };

    let authnParams = await Routes.setOrder({
      identifier,
      ip: ip,
      state: state || null,
      userAgent: ua,
    });

    //@ts-ignore
    req[authnParam] = authnParams;

    if (next) {
      next();
    }
  };

  /**
   * @param {Object} body
   * @param {Object} body.state
   * @param {String} body.ip
   * @param {String} [body.userAgent]
   * @param {Object} body.identifier
   * @param {String} body.identifier.type
   * @param {String} body.identifier.value
   */
  Routes.setOrder = async function ({ identifier, ip, state, userAgent }) {
    // TODO XXXX use parent opts?
    let opts = {};
    let c = verifier.create(
      identifier,
      {
        ip,
        userAgent,
        identifier,
        state,
      },
      opts,
    );
    c.state = state;
    let code = c.code;
    await verifier.set(c.id, c);

    // for the notify handler
    let authnParams = {
      strategy: "challenge",
      id: c.id,
      code: c.code,
      state: c.state,
      identifier: {
        type: c.identifier?.type || c.type, // email
        value: c.identifier?.value || c.value, // john.doe@gmail.com
      },
      type: c.type, // email
      value: c.value, // john.doe@gmail.com
      userAgent: c.ordered_by,
      //@ts-ignore
      issuer: opts?.iss || iss,
      //@ts-ignore
      iss: opts?.iss || iss,
      // for the client
      order: {
        id: c.id,
        duration: c.duration,
        receipt: c.receipt,
        expires_at: c.expires_at,
        // to prevent accidental JSON-ification
        getCode: function () {
          return code;
        },
      },
    };

    return authnParams;
  };

  /** @type {import('express').Handler} */
  Routes.checkStatus = async function (req, res, next) {
    let id = req.query.id || req.body.id;

    // increments failure count on bad code,
    // but doesn't consume the code on success
    let code = req.query.code || req.body.code;
    let c = await verifier.check(id, code, req);

    let status = "pending";
    if (c.canceled_by) {
      status = "invalid";
    } else if (c.verified_by) {
      status = "valid";
    }

    let authnParams = {
      success: true,
      id: id,
      status: status,
      state: c.state,
      duration: c.duration,
      ordered_at: c.ordered_at,
      ordered_by: c.ordered_by,
      canceled_at: c.canceled_at,
      canceled_by: c.canceled_by,
      verified_at: c.verified_at,
      verified_by: c.verified_by,
      expires_at: c.expires_at,
    };

    req[authnParam] = {
      id: id,
      code: code,
      _check: c,
      status: authnParams,
    };

    if (next) {
      next();
    }
    //return authnParams;
  };

  /** @type {import('express').Handler} */
  Routes.redeemCode = async function (req, res) {
    await promisifyHandler(Routes.useCode, req, res);

    let allClaims = await _strategyHandler(req, res);
    //@ts-ignore
    let authn = req[authnParam];

    //@ts-ignore
    req[authnParam] = null;

    // TODO deprecate, remove
    if (allClaims || !res.headersSent) {
      let { id_token, access_token } = await grantTokensAndCookie(
        allClaims,
        req,
        res,
      );

      res.json({
        success: true,
        status: "valid",
        state: authn.state,
        id_token: id_token,
        access_token: access_token,
      });
    }
  };

  /** @type {import('express').Handler} */
  Routes.useCode = async function (req, res, next) {
    let code =
      req.body.code || req.query.code || req.body.token || req.query.token;
    let id = req.body.id || req.query.id;
    // TODO move finalize up to this level?
    //let finalize = req.body.finalize;
    let cancel = req.body.cancel || req.query.cancel;

    if (!id || !code) {
      if (!code && !cancel) {
        throw E.DEVELOPER_ERROR(
          "'id' and/or 'code' is missing from the query parameters and/or request body",
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
      _exchange: "redeem",
      _verification: c,
      status: "valid",
      state: c.state,
      duration: c.duration,
      identifier: {
        type: c.type,
        value: c.value,
      },
      type: c.type,
      value: c.value,
      email: c.value,
      iss: c.iss,
      userAgent: c.verified_by,
      id,
    };

    next();
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
  Routes.exchangeReceipt = async function (req, res) {
    await promisifyHandler(Routes.useReceipt, req, res);

    let allClaims = await _strategyHandler(req, res);
    //@ts-ignore
    let authn = req[authnParam];
    //@ts-ignore
    req[authnParam] = null;

    // TODO deprecate
    if (allClaims || !res.headersSent) {
      let { id_token, access_token } = await grantTokensAndCookie(
        allClaims,
        req,
        res,
      );

      res.json({
        success: true,
        status: "valid",
        state: authn.state,
        id_token: id_token,
        access_token: access_token,
      });
    }
  };

  /** @type {import('express').Handler} */
  Routes.useReceipt = async function (req, res, next) {
    let id = req.body.id;
    let receipt = req.body.receipt;

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

    next();
  };

  return Routes;
};
