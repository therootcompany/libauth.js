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
      //@ts-ignore
      pluginOpts.Codes = require("./magic-code.js").create(pluginOpts);
    }

    if (!pluginOpts.Flow) {
      //@ts-ignore
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
        /** @param {any} challenge */
        set: async function (challenge) {
          memstore._db[challenge.id] = challenge;
        },
        /**
         * @param {Object} query
         * @param {String} query.id
         */
        get: async function ({ id }) {
          return memstore._db[id];
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
      let request = { identifier, state };
      let device = { ip, userAgent };
      // finalize??
      let params = { id, code, receipt, finalize };

      let magic = { device, params, request };
      libauth.set(req, "challenge", magic);

      next();
    };

    /** @type {import('express').Handler} */
    magicRoutes.generateChallenge = async function (req, res, next) {
      /** @type Challenge */
      let magic = libauth.get(req, "challenge");

      let { code, id, receipt } = pluginOpts.Codes.generate(4, "hex");

      magic.order = pluginOpts.Flow.initialize(
        { code, id, receipt },
        magic.device,
        magic.request,
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

        libauth.set(req, "challenge", magic);

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
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

      // TODO is this the best trinary state?
      magic.valid = magic.valid ?? null;
      magic.verified = magic.verified ?? null;
      // magic.validations = { code, receipt };

      if (!params.code && !params.receipt) {
        throw E.DEVELOPER_ERROR(
          "'code' or 'receipt' is missing from the request parameters",
        );
      }

      // However, failure is noted any time they are given.
      if (magic.params.code) {
        magic.verified = pluginOpts.Codes.verify(
          magic.order,
          magic.params.code,
        );
      }

      // TODO { validations: { code: true, receipt: true } }
      if (magic.params.receipt) {
        magic.valid = pluginOpts.Codes.validate(magic.order, magic.params);
      } else if (true === magic.verified) {
        magic.valid = magic.verified;
      }

      await pluginOpts.Flow.assertValid(
        magic.verified ?? magic.valid,
        magic.order,
        magic.device,
        magic.params,
      );

      // Providing an incorrect `code` or `receipt` will increment
      // the failure counter if non-expired and non-redeemed.

      // Both `code` and `receipt` function as one-time passwords
      // for a single token exchange, but they can be used multiple
      // times for status checks.
      if (false === magic.verified || false === magic.valid) {
        let redeemable = !magic.order.verified_at || !magic.order.finalized_at;
        if (redeemable) {
          // TODO better name for handleFailure?
          magic.order = await pluginOpts.Flow.handleFailure(
            magic.order,
            magic.params,
            magic.device,
          );
          libauth.set(req, "challenge", magic);

          if (false === magic.verified) {
            // Only thrown when code was attempted
            throw E.CODE_RETRY();
          }
        }

        // Thrown if receipt was bad
        throw E.CODE_NOT_FOUND();
      }

      next();
    });

    /** @type {import('express').Handler} */
    magicRoutes.exchange = async function (req, res, next) {
      /** @type Challenge */
      let magic = libauth.get(req, "challenge");

      // only gets here on success

      magic.order = await pluginOpts.Flow.redeem(
        magic.verified ?? magic.valid,
        magic.order,
        magic.device,
        magic.params,
      );

      libauth.set(req, "challenge", magic);
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
    let d = new Date(order.expires_at).valueOf();
    let fresh = d - timestamp > 0;
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
