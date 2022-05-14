"use strict";

let Magic = exports;

let E = require("./errors.js");

/**
 * @param {any} libauth
 * @param {any} libOpts
 */
Magic.create = function (libauth, libOpts) {
  /**
   * @param {any} _chOpts
   */
  return function (pluginOpts) {
    if (!chOpts.verifier) {
      //@ts-ignore
      chOpts.verifier = require("./verifier.js").create(
        libauth,
        libOpts,
        pluginOpts,
      );
    }

    let Routes = {};

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
      libauth.set(req, "receipt", authnParams);

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
      let { order, code } = chOpts.verifier.create(identifier, {
        ip,
        userAgent,
        identifier,
        state,
      });

      await pluginOpts.verifier.set(order.id, order);

      return receipt;
    };

    /** @type {import('express').Handler} */
    Routes.checkStatus = async function (req, res, next) {
      let id = req.query.id || req.body.id;

      // increments failure count on bad code,
      // but doesn't consume the code on success
      let code = req.query.code || req.body.code;
      let c = await chOpts.verifier.check(id, code, req);

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

      //@ts-ignore
      req[libOpts.authnParam] = {
        id: id,
        code: code,
        _check: c,
        status: authnParams,
      };

      next();
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
      let c = await chOpts.verifier.redeem(id, code, req);

      //@ts-ignore
      req[libOpts.authnParam] = {
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
    Routes.cancel = async function (req, res, next) {
      let id = req.body.id || req.query.id;
      let c = await chOpts.verifier.cancel(id, req);

      let receipt = {
        success: true,
        status: "invalid",
        id: id,
        canceled_at: c.canceled_at,
        canceled_by: c.canceled_by,
      };

      libauth.set(req, "receipt", receipt);

      next();
    };

    Routes.sendReceipt = async function (req, res) {
      let receipt = libauth.get(req, "receipt");

      res.json(receipt);
    };

    /** @type {import('express').Handler} */
    Routes.useReceipt = async function (req, res, next) {
      let id = req.body.id;
      let receipt = req.body.receipt;

      let c = await chOpts.verifier.exchange(id, receipt, req);

      //@ts-ignore
      req[libOpts.authnParam] = {
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
};
