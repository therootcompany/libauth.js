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
 * @property {Function} assertVerified - async function (order, code, asserts)
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
 * @property {MagicCodeVend} vender
 * @property {MagicCodeStore} store
 * @property {Number} coolDownMs
 */

/**
 * @param {any} libauth
 * @param {any} libOpts
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

    if (!pluginOpts.vender) {
      //@ts-ignore
      pluginOpts.vender = require("./magic-order.js").create(pluginOpts);
    }

    if (!pluginOpts.store) {
      console.warn(
        "[libauth] Warn: no 'store' given, falling back to in-memory (single-system only) store",
      );
      //@ts-ignore
      pluginOpts.store = require("./memory-store.js");
    }

    if (!pluginOpts.coolDownMs) {
      pluginOpts.coolDownMs = 250;
    }

    let Routes = {};

    //
    // Create
    //

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
      // finalize??
      let params = { id, code, receipt, finalize };

      let magic = { device, params, request };
      libauth.set(req, "magic", magic);

      next();
    };

    /** @type {import('express').Handler} */
    Routes.newMagicLink = async function (req, res, next) {
      let magic = libauth.get(req, "magic");

      // Security: HMAC_SECRET MUST be at least 12 bytes (96-bits).
      //
      // With that assumed, we can drop the number of required bits
      // for the code down in the range of 29~32 bits,possibly lower
      // if the number of attempts is capped below 10, and/or the time
      // window is shrunk from 20 minutes to 10m or 5m
      //
      // https://therootcompany.com/blog/how-many-bits-of-entropy-per-character/
      let { code, id, receipt } = pluginOpts.codes.generate(4, "hex");

      let order = pluginOpts.vender.initialize(
        { code, id, receipt },
        magic.device,
        magic.request,
      );

      let magicParts = {
        code,
        order,
        status,
        device: magic.device,
        request: magic.request,
      };
      libauth.set(req, "magic", magicParts);

      next();
    };

    /** @type {import('express').Handler} */
    Routes.saveOrder = async function (req, res, next) {
      let magic = libauth.get(req, "magic");

      await pluginOpts.store.set(magic.order.id, magic.order);

      next();
    };

    //
    // Read
    //

    // Routes.setOrderParams(req, res, next)

    /** @type {import('express').Handler} */
    Routes.getOrder = function (req, res, next) {
      async function mw() {
        let magic = libauth.get(req, "magic");
        if (!magic.params.id) {
          throw E.DEVELOPER_ERROR(
            "'id' is missing from the query parameters and/or request body",
          );
        }

        let order = await pluginOpts.store.get(magic.params.id);
        let magicPart = {
          order,
          // TODO down to vender?
          status: Magic._toStatus(order),
        };

        libauth.set(req, "magic", Object.assign(magicPart, magic));

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    };

    /** @type {import('express').Handler} */
    Routes.checkStatus = async function (req, res, next) {
      let magic = libauth.get(req, "magic");
      magic.params.requireExchange = false;
      libauth.set(req, "magic", magic);

      try {
        await Routes.check(req, res, next);
      } catch (err) {
        next(err);
      }
    };

    //
    // Check
    //

    // Routes.setOrderParams(req, res, next)

    /** @type {Object.<string, boolean>} */
    Routes._limitCache = {};

    /** @type {import('express').Handler} */
    Routes.rateLimitChecks = async function (req, res, next) {
      let magic = libauth.get(req, "magic");

      // TODO set here and execute where needed?

      // An attacker could grant himself hundreds or thousands of extra attempts
      // by firing off many requests in parallel - the database might read
      // `attempts = 0` 1000 times and then write `attempts = 1` 1000 times, and
      // then repeat for `attempts = 1`, etc.
      //
      // To prevent this disallow parallel requests.
      // (note: a scalable server system will need a more sophisticated approach)

      libauth.set(req, "magicLimit", true);
      if (Routes._limitCache[magic.params.id]) {
        await Util.sleep(pluginOpts.coolDownMs);
        throw E.ENHANCE_YOUR_CALM();
      }
      next();
    };

    /*
    Routes._chillax = async function (id) {
      if (Routes._limitCache[magic.params.id]) {
        await Util.sleep(pluginOpts.coolDownMs);
        throw E.ENHANCE_YOUR_CALM();
      }
    };
    */

    /**
     * @param {String} id
     * @param {Function} fn
     */
    Routes._lock = async function (id, fn) {
      Routes._limitCache[id] = true;

      let err;
      try {
        // not using .catch because this may be async or sync
        await fn();
      } catch (_err) {
        err = _err;
      }

      // always delete the attempt
      delete Routes._limitCache[id];
      if (err) {
        throw err;
      }
    };

    // Routes.saveOrder(req, res, next)

    /** @type {import('express').Handler} */
    Routes.exchange = async function (req, res, next) {
      let magic = libauth.get(req, "magic");
      magic.params.requireExchange = true;
      libauth.set(req, "magic", magic);

      // TODO could we move this into check?
      if (!magic.code && !magic.receipt) {
        throw E.DEVELOPER_ERROR(
          "'code' and/or 'receipt' is missing from the query parameters and/or request body",
        );
      }

      try {
        await Routes.check(req, res, next);
      } catch (err) {
        next(err);
      }
    };

    // This is fundamentally complicated because the status check
    // and exchange have nearly identical code paths, except for
    // a few key options.
    // Open to suggestions...
    /** @type {import('express').Handler} */
    Routes.check = async function (req, res, next) {
      let magic = libauth.get(req, "magic");
      let code = req.query.code || req.body.code;

      async function mw() {
        // Providing an incorrect `code` or `receipt` will always
        // increment the failure counter.
        //
        // Both `code` and `receipt` function as one-time passwords
        // for a single token exchange, but when `requireExchange: false`
        // they can be used multiple times for status checks.
        magic.params.requireExchange = magic.params.requireExchange ?? true;

        if (magic.params.code || magic.params.requireExchange) {
          await Routes._lock(magic.order.id, check);
        } else {
          await check();
        }

        async function check() {
          let assertOpts = {
            requireUnusedCode: false,
            requireUnusedReceipt: false,
            requireExchange: magic.params.requireExchange,
          };
          if (assertOpts.requireExchange) {
            if (magic.params.code) {
              assertOpts.requireUnusedCode = true;
            } else if (magic.params.receipt) {
              assertOpts.requireUnusedReceipt = true;
            }
          }

          try {
            libauth.set(req, "magicAsserts", assertOpts);
            let { status } = await pluginOpts.vender.assertValid(
              magic.order,
              magic.params.code,
              assertOpts,
            );

            magic = Object.assign({}, magic, { status });
            libauth.set(req, "magic", magic);
            next();
          } catch (err) {
            await Routes.incrementOnRetry(err, req, res, next);
            return;
          }

          next();
        }
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    };

    /** @type {import('express').Handler} */
    Routes.redeem = async function (req, res, next) {
      let magic = libauth.get(req, "magic");
      let assertOpts = libauth.get(req, "magicAsserts");

      // TODO

      await pluginOpts.vender.assertVerified(
        magic.order,
        magic.params.code,
        assertOpts,
      );

      let { order, status } = await pluginOpts.vender.redeem(
        magic.order,
        magic.params,
        req,
      );

      magic.verified = true;
      libauth.set(req, "magic", magic);
    };

    /** @type {import('express').ErrorRequestHandler} */
    Routes.incrementOnRetry = function (err, req, res, next) {
      if (!err.E_CODE_RETRY || "E_CODE_RETRY" !== err.code) {
        next(err);
        return;
      }

      async function mw() {
        let magic = libauth.get(req, "magic");
        let order = magic.order;

        // TODO in error handler
        await pluginOpts.vender.increment(order);
        next(next);
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    };

    //
    // Delete
    //

    /** @type {import('express').Handler} */
    Routes.cancel = async function (req, res, next) {
      let id = req.body.id || req.query.id;
      let c = await pluginOpts.vender.cancel(id, req);

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

    //
    // Send
    //

    /** @type {import('express').Handler} */
    Routes.sendStatus = async function (req, res) {
      let magic = libauth.get(req, "magic");

      res.json(magic.status);
    };

    /** @type {import('express').Handler} */
    Routes.sendReceipt = async function (req, res) {
      let magic = libauth.get(req, "magic");

      res.json(
        Object.assign(
          {
            receipt: magic.order.receipt,
          },
          magic.status,
        ),
      );
    };

    return Routes;
  };
};

/**
 * @param {MagicOrder} order
 * @returns {MagicStatus}
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
