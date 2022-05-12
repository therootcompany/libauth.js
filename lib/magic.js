"use strict";

let Magic = exports;

Magic.create = function (libauth, _opts) {
  if (!_opts.store) {
    console.warn(
      "[libauth] Warn: no 'store' given, falling back to in-memory (single-system only) store",
    );
    _opts.store = require("./memory-store.js");
  }

  if (!_opts.verifier) {
    //@ts-ignore
    _opts.verifier = require("./verifier.js").create({
      // important
      //@ts-ignore
      store: _opts.store,

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

  //@ts-ignore
  if ("function" === typeof _opts.verifier.setDefaults) {
    //@ts-ignore
    _opts.verifier.setDefaults({
      iss: libauth.issuer(_opts), // opts.issuer,
      //@ts-ignore
      secret: _opts.secret,
      //@ts-ignore
      authnParam: libauth.reqparam(_opts), // _opts.authnParam,
    });
  }

  let _challengeRoutes = require("./magic-link.js").createRouter({
    iss: libauth.issuer(_opts), // opts.issuer,
    verifier: _opts.verifier,
    //@ts-ignore
    authnParam: libauth.reqparam(_opts), // _opts.authnParam,
  });

  return _challengeRoutes;
};
