"use strict";

let Magic = exports;

/**
 * @param {any} libauth
 * @param {any} _opts
 */
Magic.create = function (libauth, _opts) {
  /**
   * @param {any} userOpts
   */
  return function (userOpts = {}) {
    if (!userOpts.store) {
      userOpts.store = _opts.store;
    }
    if (!userOpts.store) {
      console.warn(
        "[libauth] Warn: no 'store' given, falling back to in-memory (single-system only) store",
      );
      userOpts.store = require("./memory-store.js");
    }

    if (!_opts.verifier) {
      //@ts-ignore
      _opts.verifier = require("./verifier.js").create({
        // important
        //@ts-ignore
        store: userOpts.store,

        // optional
        coolDownMs: 250,
        idByteCount: 4,
        idEncoding: "base64",
        maxAge: _opts.maxAge,
        maxAttempts: _opts.maxAttempts,
        receiptByteCount: 16,
        receiptEncoding: "base64",
      });
    }

    if ("function" === typeof _opts.verifier.setDefaults) {
      //@ts-ignore
      _opts.verifier.setDefaults({
        iss: _opts.issuer || libauth.issuer(_opts),
        //@ts-ignore
        secret: _opts.secret,
        //@ts-ignore
        authnParam: _opts.authnParam || libauth.reqparam(_opts),
      });
    }

    let _challengeRoutes = require("./magic-link.js").createRouter({
      iss: _opts.issuer || libauth.issuer(_opts),
      verifier: _opts.verifier,
      //@ts-ignore
      authnParam: _opts.authnParam || libauth.reqparam(_opts),
    });

    return _challengeRoutes;
  };
};
