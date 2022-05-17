"use strict";

let Magic = exports;

let E = require("./errors.js");

/**
 * @param {any} libauth
 * @param {any} libOpts
 */
Magic.create = function (libauth, libOpts) {
  /**
   * @param {any} pluginOpts
   */
  return function (pluginOpts) {
    if (!pluginOpts.verifier) {
      //@ts-ignore
      pluginOpts.verifier = require("./verifier.js").create(
        libOpts.issuer,
        libOpts.secret,
        pluginOpts,
      );
    }

    let Routes = {};

    /** @type {import('express').Handler} */
    Routes.setOrderParams = async function (req, res, next) {
      let id = req.body.id || req.query.id;
      let code = req.body.code || req.query.code;
      let receipt = req.body.receipt || req.query.receipt;
      let finalize = req.body.finalize || req.query.finalize;
      let identifier = req.body.identifier;
      let state = req.body.state;

      let userAgent = req.headers["user-agent"] || "";
      let ip = req.ip || "";

      // TODO identifier_type, identifier_value
      if (identifier) {
        identifier = {
          // TODO issuer:
          type: identifier.type,
          value: (identifier.value || "").trim().toLowerCase(),
        };
      }
      let request = { identifier, state };
      let device = { ip, userAgent };
      let params = { id, code, receipt, finalize };
      let magic = { id, code, receipt, request, device, params };

      libauth.set(req, "magic", magic);

      next();
    };

    /** @type {import('express').Handler} */
    Routes.getOrderById = function (req, res, next) {
      async function mw() {
        let magic = libauth.get(req, "magic");
        let order = await pluginOpts.store.get(magic.id);
        let magicPart = {
          order,
          // TODO down to verifier?
          status: Magic._toStatus(order),
        };

        libauth.set(req, "magic", Object.assign(magicPart, magic));

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    };

    /** @type {import('express').Handler} */
    Routes.newMagicLink = async function (req, res, next) {
      let magic = libauth.get(req, "magic");
      let { order, code } = pluginOpts.verifier.create(
        magic.device,
        magic.params,
      );

      next();
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
      let { order, code } = pluginOpts.verifier.create(identifier, {
        ip,
        userAgent,
        identifier,
        state,
      });

      await pluginOpts.verifier.set(order.id, order);
    };

    /** @type {import('express').Handler} */
    Routes.checkStatus = async function (req, res, next) {
      let id = req.query.id || req.body.id;

      // increments failure count on bad code,
      // but doesn't consume the code on success
      let code = req.query.code || req.body.code;
      let c = await pluginOpts.verifier.check(id, code, req);

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
      let id = req.body.id || req.query.id;
      let code =
        req.body.code || req.query.code || req.body.token || req.query.token;

      if (!id || !code) {
        throw E.DEVELOPER_ERROR(
          "'id' and/or 'code' is missing from the query parameters and/or request body",
        );
      }

      // increments failure count on bad code
      let { order } = await pluginOpts.verifier.redeem(id, code, req);
      let status = Magic._toStatus(order);

      libauth.set(req, "magicLink", { order, status });

      next();
    };

    /*
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

     */

    /** @type {import('express').Handler} */
    Routes.cancel = async function (req, res, next) {
      let id = req.body.id || req.query.id;
      let c = await pluginOpts.verifier.cancel(id, req);

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

    /** @type {import('express').Handler} */
    Routes.sendReceipt = async function (req, res) {
      let receipt = libauth.get(req, "receipt");

      res.json(receipt);
    };

    /** @type {import('express').Handler} */
    Routes.useReceipt = async function (req, res, next) {
      let id = req.body.id;
      let receipt = req.body.receipt;

      let c = await pluginOpts.verifier.exchange(id, receipt, req);

      //@ts-ignore
      libauth.set(req, {
        strategy: "challenge",
        identifier: {
          issuer: c.issuer || c.iss,
          type: c.type,
          value: c.value,
        },
        receipt: {
          id,
          receipt,
          state: c.state,
        },
        _exchange: "exchange",
        _verification: c,
        duration: c.duration,
        type: c.type,
        value: c.value,
        email: c.value,
        iss: c.iss,
        userAgent: c.exchanged_by,
      });

      next();
    };

    return Routes;
  };
};

/**
 * @param {Challenge} order
 */
Magic._toStatus = function (order) {
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

/**
 * @param {Challenge} order
 */
/*
Magic._toReceipt = function (order) {
  return {
    id: order.id,
    receipt: order.receipt,
    duration: order.duration,
  };
};
*/
