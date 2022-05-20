"use strict";

let Magic = exports;

let E = require("./errors.js");

let Util = require("./util.js");

/**
 * @typedef MagicCodeGen
 * @property {Function} generate
 * @property {Function} verify
 */

/**
 * @typedef MagicCodeVend
 * @property {Function} initialize - function (parts, device, request)
 * @property {Function} assertValid - async function (order, code, asserts)
 * @property {Function} redeem - async function (order, params, device)
 * @property {Function} increment - function (order)
 * @property {Function} cancel = function (order, device)
 */

/**
 * @typedef MagicCodeStore
 * @property {Function} get
 * @property {Function} set
 */

/**
 * @typedef MagicRouteOpts
 * @property {MagicCodeGen} codes
 * @property {MagicCodeVend} flow
 * @property {MagicCodeStore} store
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
    if (!pluginOpts.codes) {
      //@ts-ignore
      pluginOpts.codes = require("./magic-code.js").create(pluginOpts);
    }

    if (!pluginOpts.flow) {
      //@ts-ignore
      pluginOpts.flow = require("./magic-flow.js").create(pluginOpts);
    }

    if (!pluginOpts.store) {
      console.warn(
        "[libauth] Warn: no 'store' given, falling back to in-memory (single-system only) store",
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
      pluginOpts.store = memstore;
    }

    if (!pluginOpts.coolDownMs) {
      pluginOpts.coolDownMs = 250;
    }

    let magicRoutes = {};

    //
    // Create
    //

    /** @type {import('express').Handler} */
    magicRoutes.setParams = async function (req, res, next) {
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
      let magic = libauth.get(req, "challenge");

      let { code, id, receipt } = pluginOpts.codes.generate(4, "hex");

      magic.order = pluginOpts.flow.initialize(
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
      let magic = libauth.get(req, "challenge");

      await pluginOpts.store.set(magic.order);

      next();
    };

    /** @type {import('express').Handler} */
    magicRoutes.reviveError = async function (req, res, next) {
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
        let magic = libauth.get(req, "challenge");
        if (!magic.params.id) {
          throw E.DEVELOPER_ERROR(
            "'id' is missing from the query parameters and/or request body",
          );
        }

        magic.order = await pluginOpts.store.get({
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
      let magic = libauth.get(req, "challenge");

      // Providing an incorrect `code` or `receipt` will always
      // increment the failure counter.
      //
      // Both `code` and `receipt` function as one-time passwords
      // for a single token exchange, but when `requireExchange: false`
      // they can be used multiple times for status checks.

      let assertOpts = {
        requireExchange: magic.params.requireExchange,
        failedVerification: false,
      };

      // In some cases coder and/or receipt are optional.
      // However, failure is noted any time they are given.
      if (magic.params.code || magic.params.receipt) {
        let pass = pluginOpts.codes.verify(magic.order, magic.params);
        assertOpts.failedVerification = !pass;
        magic.verified = true;
        libauth.set(req, "challenge", magic);
      } else if (assertOpts.requireExchange) {
        throw E.DEVELOPER_ERROR(
          "'code' and/or 'receipt' is missing from the query parameters and/or request body",
        );
      }

      await pluginOpts.flow.assertValid(magic.order, magic.params, assertOpts);

      next();
    });

    /** @type {import('express').Handler} */
    magicRoutes.exchange = async function (req, res, next) {
      let magic = libauth.get(req, "challenge");
      magic.params.requireExchange = true;
      libauth.set(req, "challenge", magic);

      try {
        await magicRoutes.checkStatus(req, res, next);
      } catch (err) {
        next(err);
      }
    };

    /** @type {import('express').Handler} */
    magicRoutes.verifyResponse = async function (req, res, next) {
      let magic = libauth.get(req, "challenge");

      if (true !== magic.verified) {
        magic.order = await pluginOpts.flow.increment(
          magic.order,
          magic.device,
        );
        libauth.set(req, "challenge", magic);
        throw E.CODE_RETRY();
      }

      magic.order = await pluginOpts.flow.redeem(
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
      let magic = libauth.get(req, "challenge");
      magic.order = await pluginOpts.flow.cancel(magic.order, magic.device);

      libauth.set(req, "challenge", magic);

      next();
    };

    //
    // Send
    //

    /** @type {import('express').Handler} */
    magicRoutes.sendStatus = async function (req, res) {
      let magic = libauth.get(req, "challenge");
      let status = Magic.toStatus(magic.order);

      res.json(status);
    };

    /** @type {import('express').Handler} */
    magicRoutes.sendReceipt = async function (req, res) {
      let magic = libauth.get(req, "challenge");
      let status = Magic.toStatus(magic.order, magic.order.recepit);

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
  } else if (order.verified_by) {
    status = "valid";
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
    ordered_at: order.ordered_at,
    ordered_by: order.ordered_by,
    verified_at: order.verified_at,
    verified_by: order.verified_by,
  };
};
