"use strict";

let Magic = exports;

let E = require("./errors.js");

let Util = require("./util.js");

/**
 * @typedef MagicRouteOpts
 * @property {MagicCodeGen} Codes
 * @property {MagicCodeFlow} Flow
 * @property {MagicCodeStore} Store
 * @property {Number} coolDownMs
 */

/**
 * @param {LibAuth} libauth
 * @param {LibAuthOpts} libOpts
 */
Magic.create = function (libauth, libOpts) {
  /**
   * @param {MagicVerifierOpts & MagicCodeOpts & MagicRouteOpts} pluginOpts
   */
  return function (pluginOpts) {
    if (!pluginOpts.Codes) {
      pluginOpts.Codes = require("./magic-code.js").create(pluginOpts);
    }

    if (!pluginOpts.Flow) {
      pluginOpts.Flow = require("./magic-flow.js").create(pluginOpts);
    }

    if (!pluginOpts.Store) {
      console.warn(
        "[libauth] Warn: no 'Store' given, falling back to in-memory (single-system only) store",
      );
      // TODO move out?
      let memstore = {
        /** @type {Record<String, any>} */
        _db: {},
        /** @param {MagicOrder} order */
        set: async function (order) {
          memstore._db[order.id] = order;
          if (order.identifier?.value) {
            memstore._db[`${order.identifier.type}:${order.identifier.value}`] =
              order;
          }
        },
        /**
         * @param {Object} query
         * @param {String} query.id
         * @param {Object} query.identifier
         * @param {String} query.identifier.type
         * @param {String} query.identifier.value
         */
        get: async function (query) {
          let result = memstore._db[query.id];
          if (!result && query.identifier?.value) {
            result =
              memstore._db[
                `${query.identifier.type}:${query.identifier.value}`
              ];
          }
          return result;
        },
      };
      pluginOpts.Store = memstore;
    }

    if (!pluginOpts.coolDownMs) {
      pluginOpts.coolDownMs = 250;
    }

    let magicRoutes = {};

    //
    // Create
    //

    /** @type {import('express').Handler} */
    magicRoutes.readParams = async function (req, res, next) {
      let challenge = libauth.get(req, "challenge") || {};

      if (!challenge.device) {
        challenge.device = {};
      }
      if (!challenge.params) {
        challenge.params = {};
      }
      if (!challenge.request) {
        challenge.request = {};
      }

      let id = req.params.id || req.body.id || req.query.id;
      let code = req.body.code || req.query.code;
      let receipt = req.body.receipt || req.query.receipt;
      let finalize = req.body.finalize || req.query.finalize;
      let identifier = req.body.identifier;
      let state = req.body.state;

      let userAgent = req.headers["user-agent"] || "";
      let ip = req.ip || "";

      // TODO Authorization: Basic b64(code:xxxxx)
      // TODO Authorization: Basic b64(receipt:xxxxx)

      // TODO identifier_type, identifier_value ?
      if (identifier) {
        identifier = {
          // TODO issuer:
          type: identifier.type,
          value: (identifier.value || "").trim().toLowerCase(),
        };
      }

      challenge.device = Object.assign({ ip, userAgent }, challenge.device);
      challenge.params = Object.assign(
        { id, code, receipt, finalize },
        challenge.params,
      );
      // TODO identifier_type, identifier_value ??
      challenge.request = Object.assign(
        { identifier, state },
        challenge.request,
      );

      libauth.set(req, "challenge", challenge);

      next();
    };

    /** @type {import('express').Handler} */
    magicRoutes.generateChallenge = async function (req, res, next) {
      /** @type Challenge */
      let magic = libauth.get(req, "challenge");

      let { code, id, receipt } = await pluginOpts.Codes.generate({});

      console.log("DEBUG:", { code, id, receipt });
      magic.order = pluginOpts.Flow.initialize(
        { code, id, receipt },
        magic.request,
        magic.device,
      );
      magic.code = code;

      libauth.set(req, "challenge", magic);

      next();
    };

    /** @type {import('express').Handler} */
    magicRoutes.saveChallenge = async function (req, res, next) {
      /** @type Challenge */
      let magic = libauth.get(req, "challenge");

      await pluginOpts.Store.set(magic.order);

      next();
    };

    // TODO better name?
    /** @type {import('express').ErrorRequestHandler} */
    magicRoutes.saveFailedChallenge = async function (err, req, res, next) {
      if (err.E_CODE_RETRY || "E_CODE_RETRY" === err.code) {
        /** @type Challenge */
        let magic = libauth.get(req, "challenge");

        await pluginOpts.Store.set(magic.order);
      }

      next(err);
    };

    /** @type {import('express').Handler} */
    magicRoutes.reviveError = async function (req, res, next) {
      /** @type Error */
      let err = libauth.get(req, "error");
      if (err) {
        next(err);
        return;
      }
      next();
    };

    //
    // Read
    //

    /** @type {import('express').Handler} */
    magicRoutes.getChallenge = function (req, res, next) {
      async function mw() {
        /** @type Challenge */
        let magic = libauth.get(req, "challenge");
        if (!magic.params.id) {
          throw E.DEVELOPER_ERROR(
            "'id' is missing from the query parameters and/or request body",
          );
        }

        magic.order = await pluginOpts.Store.get({
          id: magic.params.id,
          request: magic.request,
        });
        if (!magic.order) {
          throw E.CODE_NOT_FOUND();
        }

        libauth.set(req, "challenge", magic);

        next();
      }

      Promise.resolve().then(mw).catch(next);
    };

    //
    // Check
    //

    // This is fundamentally complicated because the status check
    // and exchange have nearly identical code paths, except for
    // a few key options.
    // Open to suggestions...
    /** @type {import('express').Handler} */
    magicRoutes.checkStatus = libauth.promisifyHandler(async function (
      req,
      res,
      next,
    ) {
      /** @type Challenge */
      let magic = libauth.get(req, "challenge");
      let params = magic.params;

      if (!params.code && !params.receipt) {
        throw E.DEVELOPER_ERROR(
          "'code' or 'receipt' is missing from the request parameters",
        );
      }

      magic.validations = await pluginOpts.Codes.validate(
        magic.order,
        magic.params,
        magic.device,
        {},
      );
      libauth.set(req, "challenge", magic);

      await pluginOpts.Flow.assertValid(
        magic.validations,
        magic.order,
        magic.params,
        magic.device,
      );

      // Providing an incorrect `code` or `receipt` will increment
      // the failure counter if non-expired and non-redeemed.

      // Both `code` and `receipt` function as one-time passwords
      // for a single token exchange, but they can be used multiple
      // times for status checks.
      // if (!magic.validations.valid) {
      if (magic.validations.code || magic.validations.receipt) {
        next();
        return;
      }

      let redeemable = !magic.order.verified_at || !magic.order.finalized_at;
      if (redeemable) {
        magic.order = await pluginOpts.Flow.handleFailure(
          magic.order,
          magic.params,
          magic.device,
        );
        libauth.set(req, "challenge", magic);
      }

      throw E.CODE_RETRY();
    });

    /** @type {import('express').Handler} */
    magicRoutes.exchange = async function (req, res, next) {
      /** @type Challenge */
      let magic = libauth.get(req, "challenge");

      // only gets here on success

      magic.order = await pluginOpts.Flow.redeem(
        magic.validations,
        magic.order,
        magic.params,
        magic.device,
      );

      libauth.set(req, "authMethods", [
        `challenge:${magic.order.identifier.type}`,
      ]);
      libauth.set(req, "challenge", magic);

      next();
    };

    //
    // Delete
    //

    /** @type {import('express').Handler} */
    magicRoutes.cancelChallenge = async function (req, res, next) {
      /** @type Challenge */
      let magic = libauth.get(req, "challenge");
      magic.order = await pluginOpts.Flow.cancel(
        magic.order,
        magic.params,
        magic.device,
      );

      libauth.set(req, "challenge", magic);

      next();
    };

    //
    // Send
    //

    /** @type {import('express').Handler} */
    magicRoutes.sendStatus = async function (req, res) {
      /** @type Challenge */
      let magic = libauth.get(req, "challenge");
      let status = Magic.toStatus(magic.order);

      res.json(status);
    };

    /** @type {import('express').Handler} */
    magicRoutes.sendReceipt = async function (req, res) {
      /** @type Challenge */
      let magic = libauth.get(req, "challenge");
      let status = Magic.toStatus(magic.order, magic.order.receipt);

      res.json(status);
    };

    return magicRoutes;
  };
};

/**
 * @param {MagicOrder} order
 * @param {String} [receipt]
 * @returns {MagicStatus}
 */
Magic.toStatus = function (order, receipt) {
  let status = "pending";
  if (order.canceled_by) {
    status = "invalid";
  } else if (order.finalized_at) {
    status = "finalized";
  } else {
    let timestamp = Date.now();
    let exp = new Date(order.expires_at).valueOf();
    let fresh = exp - timestamp > 0;
    if (!fresh) {
      status = "expired";
    } else if (order.verified_by) {
      status = "valid";
    }
  }

  return {
    id: order.id,
    receipt: receipt,
    status: status,
    // TODO always include?
    // receipt: receipt,
    state: order.state,
    duration: order.duration,
    expires_at: order.expires_at,
    canceled_at: order.canceled_at,
    canceled_by: order.canceled_by,
    exchanged_at: order.exchanged_at,
    finalized_at: order.finalized_at,
    ordered_at: order.ordered_at,
    ordered_by: order.ordered_by,
    verified_at: order.verified_at,
    verified_by: order.verified_by,
  };
};
