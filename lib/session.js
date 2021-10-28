"use strict";

let bodyParser = require("body-parser");
let cookieParser = require("cookie-parser");

// JWT Stuff
//@ts-ignore
let Keyfetch = require("keyfetch");
// TODO update to @root/keypairs
//@ts-ignore
let Keypairs = require("keypairs");

//
// Helper functions
//
let E = require("./errors.js");
let rnd = require("./rnd.js");
let parseDuration = require("./parse-duration.js");

/**
 * //TODO move to keypairs
 * @typedef {Object} Keypair
 * @property {JwsPriv} private
 * @property {JwsPub} public
 */

/**
 * @param {string} PRIVATE_KEY
 * @param {Keypair} keypair
 * @returns {Promise<void>}
 */
async function parsePrivateKey(PRIVATE_KEY, keypair) {
  if ("string" !== typeof PRIVATE_KEY) {
    PRIVATE_KEY = JSON.stringify(PRIVATE_KEY);
  }
  return Keypairs.parse({ key: PRIVATE_KEY })
    .catch(
      /** @param {Error} e */
      function (e) {
        // could not be parsed or was a public key
        if (PRIVATE_KEY) {
          console.warn(
            "[auth3000] Warn: 'PRIVATE_KEY' could not be parsed! Generating a temporary key."
          );
          console.warn(e);
        } else {
          console.warn(
            "[auth3000] Warn: 'PRIVATE_KEY' was not given. Generating an ephemeral (temporary) key."
          );
        }
        return Keypairs.generate();
      }
    )
    .then(
      /** @param {Keypair} _keypair */
      function (_keypair) {
        keypair.private = _keypair.private;
        keypair.public = _keypair.public;
      }
    );
}
/*
if (keypair.private) {
  if (!keypair.public) {
    keypair.public = JSON.parse(
      JSON.stringify({
        kty: keypair.private.kty,
        crv: keypair.private.crv,
        x: keypair.private.x,
        y: keypair.private.y,
        alg: keypair.private.alg,
        e: keypair.private.e,
        n: keypair.private.n,
        kid: keypair.private.kid,
      })
    );
  }
  if (!keypair.kid) {
    // Thumbprint a JWK (SHA256)
    Keypairs.thumbprint({ jwk: keypair.private }).then(function (thumb) {
      keypair.kid = thumb;
    });
  }
}
*/

/**
 * @param {OidcVerifyOpts} verifyOpts
 * @param {function} verifier
 * @returns {import('express').Handler}
 */
function verifyOidcToken(verifyOpts, verifier) {
  if (!verifier) {
    verifier = async function () {};
  }

  // Only tokens signed by the expected issuer (such as https://accounts.google.com) are valid
  return function (req, res, next) {
    let jwt = (req.headers.authorization || "").replace(/^Bearer /, "");
    Keyfetch.jwt
      .verify(jwt, verifyOpts)
      .then(
        /**
         * @param {Jws} decoded
         */
        async function (decoded) {
          if (decoded.claims.iss != verifyOpts.iss) {
            // a failsafe for older versions of keyfetch with ['*'] by default
            throw new Error(
              `unexpectedly passed issuer validation: '${decoded.claims.iss}' does not match '${verifyOpts.iss}'`
            );
          }
          await verifier(decoded);
          // just in case
          if (decoded.claims.email) {
            decoded.claims.email = decoded.claims.email.toLowerCase();
          }

          // "jws" is the technical term for a decoded "jwt"
          //@ts-ignore
          req._jws = decoded;
          next();
        }
      )
      .catch(next);
  };
}

let defaultIdMaxAge = "24h";
let defaultAccessMaxAge = "1h";
let defaultRefreshMaxAge = "7d";

/**
 * @param {string} issuer
 * @param {JwsPriv} PRIVATE_KEY
 * @param {Object} myOptions
 */
module.exports = function (issuer, PRIVATE_KEY, myOptions) {
  let app = require("@root/async-router").Router();
  /** @type {function} */
  let strategyHandler;
  /** @type {function} */
  let refreshClaims;
  /** @type {function} */
  let exchangeClaims;

  let opts = {
    issuer: issuer,
    oidc: {},
    challenge: {
      idByteCount: 4,
      /** @type {import('crypto').BinaryToTextEncoding} */
      idEncoding: "base64",
      maxAge: "24h",
      maxAttempts: 5,
      notify: null,
      receiptByteCount: 16,
      /** @type {import('crypto').BinaryToTextEncoding} */
      receiptEncoding: "base64",
      /** @type {import('./memory-store.js').MemoryStore} */
      //@ts-ignore
      store: null,
    },
    //@ts-ignore
    verifier: null,
    oauth2: {},
    /** @type {function} */
    //@ts-ignore
    notify: null,
    /** @type {import('./memory-store.js').MemoryStore} */
    //@ts-ignore
    store: null,
    challengeMaxAge: 0,
    challengeMaxAttempts: 0,
    authnParam: "authn",
    DEVELOPMENT: "DEVELOPMENT" === process.env.ENV,
    _developmentSendChallengeSecret: false,
    // assigned elsewhere
    secret: "",
    logout:
      /**
       * @param {import('express').Request} req
       */
      async function (req) {},
    // internal state
    __DEVELOPMENT: false,
    __INIT: false,
    _byChallenge: false,
  };

  // Cookie Stuff
  // See https://github.com/BeyondCodeBootcamp/beyondcodebootcamp.com/blob/main/articles/express-cookies-cheatsheet.md
  /** @type {import('express').CookieOptions} */
  let cookieDefaults = {
    signed: true,
    //path: "/api/authn/", // will be set by first middleware
    httpOnly: true,
    sameSite: "strict",
    secure: true,
    //expires: 0, // should be set on each issuance
  };

  // it is possible that this _might_ not happen until a millisecond
  // or two _after_ the server is accepting connections
  // See https://github.com/therootcompany/auth3000/issues/8
  /** @type {Keypair} */
  //@ts-ignore
  let keypair = {};
  if (PRIVATE_KEY) {
    if ("string" !== typeof PRIVATE_KEY) {
      keypair.private = PRIVATE_KEY;
    }
  }
  if (PRIVATE_KEY && !keypair.private) {
    try {
      //@ts-ignore
      PRIVATE_KEY = require("fs").readFileSync(PRIVATE_KEY, "utf8").trim();
      console.warn(
        "[auth3000] Warn: providing a private key file path is deprecated. Provide a JWK object instead."
      );
    } catch (e) {
      // ignore, probably wasn't a file anyway
      console.warn(
        "[auth3000] Warn: Providing a private key string or file path is deprecated. " +
          "\n          Run JSON.parse() on the JWK beforehand."
      );
    }
    try {
      //@ts-ignore
      keypair.private = JSON.parse(PRIVATE_KEY);
    } catch (e) {
      throw new Error(
        "[auth3000] Private Key is not in JWK format. " +
          "\n          Providing a PEM string or file path is no supported in v0.12+. " +
          "\n          Use @root/keypairs to parse PEM files."
      );
    }
  }
  // really more to get public key, or generate if no key is given
  //@ts-ignore
  parsePrivateKey(PRIVATE_KEY, keypair);

  // fill in ID claims defaults
  /**
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   */
  async function _strategyHandler(req, res) {
    let __strategyHandler;
    //@ts-ignore
    switch (req[opts.authnParam].strategy) {
      case "refresh":
        __strategyHandler = refreshClaims || strategyHandler;
        break;
      case "jwt":
      /* falls through */
      case "exchange":
        __strategyHandler = exchangeClaims || strategyHandler;
        break;
      case "challenge":
      /* falls through */
      case "oidc":
      /* falls through */
      case "oauth2":
      /* falls through */
      case "credentials":
      /* falls through */
      default:
        __strategyHandler = strategyHandler;
    }
    let { claims, id_claims, access_claims, refresh_claims } =
      await __strategyHandler(req, res);
    if (!claims) {
      claims = {};
    }
    if (!claims.iss && false !== claims.iss) {
      claims.iss = opts.issuer;
    }
    return { claims, id_claims, access_claims, refresh_claims };
  }

  /**
   * @param {MyAllClaims} allClaims
   * @param {import('express').Request} [req]
   * @param {import('express').Response} [res]
   */
  async function grantTokens(allClaims, req, res) {
    let id_token;
    let access_token;

    if (allClaims.claims || allClaims.id_claims) {
      let id_claims = Object.assign(
        {},
        allClaims.claims || {},
        allClaims.id_claims || {}
      );
      id_token = await Keypairs.signJwt({
        jwk: keypair.private,
        iss: opts.issuer,
        exp: id_claims.exp || defaultIdMaxAge,
        // optional claims
        claims: id_claims,
      });
    }

    if (allClaims.access_claims) {
      let access_claims = Object.assign(
        {},
        allClaims.claims || {},
        allClaims.access_claims || {}
      );
      access_token = await Keypairs.signJwt({
        jwk: keypair.private,
        iss: opts.issuer,
        exp: access_claims.exp || defaultAccessMaxAge,
        // optional claims
        claims: access_claims,
      });
    }

    return { id_token, access_token };
  }

  /**
   * @param {MyAllClaims} allClaims
   * @param {import('express').Request} req
   */
  async function grantCookie(allClaims, req) {
    if (req.body) {
      allClaims.trust_device = req.body.trust_device;
    }

    let refresh_claims = Object.assign(
      {},
      allClaims.claims || {},
      allClaims.refresh_claims || allClaims.id_claims || {}
    );
    let maxAge = refresh_claims.exp || defaultRefreshMaxAge;
    let refresh_token = await Keypairs.signJwt({
      jwk: keypair.private,
      iss: opts.issuer,
      exp: maxAge,
      claims: refresh_claims,
    });

    let cookieOpts = Object.assign({}, cookieDefaults, {
      maxAge: parseDuration(maxAge),
    });

    return { refresh_token, options: cookieOpts };
  }

  /**
   * @param {{
   *  refresh_token: String,
   *  options: any
   * }} cookie
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   */
  async function resetCookie({ refresh_token, options }, req, res) {
    // expire the old cookie in the db
    if (req.signedCookies.refresh_token) {
      await verifySession(req)
        .then(async function (jws) {
          //@ts-ignore
          req[opts.authnParam] = { jti: jws.claims.jti, jws };
          if (opts.logout) {
            await opts.logout(req);
          }
        })
        .catch(function () {
          // ignore invalid
        });
    }
    res.cookie("refresh_token", refresh_token, options);
  }

  // TODO deprecate & remove
  /**
   * @param {MyAllClaims} allClaims
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   */
  // TODO deprecate & remove
  async function grantTokensAndCookie(allClaims, req, res) {
    let { id_token, access_token } = await grantTokens(allClaims);
    let cookie = await grantCookie(allClaims, req);
    await resetCookie(cookie, req, res);
    return { id_token, access_token };
  }

  /**
   * @param {import('express').Request} req
   */
  async function verifySession(req) {
    if (!req.signedCookies.refresh_token) {
      throw E.SESSION_INVALID();
    }

    return Keyfetch.jwt.verify(req.signedCookies.refresh_token, {
      iss: opts.issuer,
    });
  }

  /**
   * @param {import('express').Request} req
   */
  async function verifyIdToken(req) {
    let jwt = (req.headers.authorization || "").replace("Bearer ", "");
    let pub;

    if (keypair) {
      pub = keypair.public;
    }

    let jws = await Keyfetch.jwt.verify(jwt, {
      issuers: [opts.issuer], // or ['*']
      jwk: pub,
    });

    return jws;
  }

  /**
   * @param {string} jwt
   * @returns {Promise<Jws>}
   */
  async function verifyJwt(jwt) {
    let pub;
    if (keypair) {
      pub = keypair.public;
    }
    let jws = await Keyfetch.jwt.verify(jwt, {
      issuers: [opts.issuer], // or ['*']
      jwk: pub,
    });
    return jws;
  }

  function router() {
    _init();

    // Dev / Localhost Stuff
    if (opts.DEVELOPMENT && !opts.__DEVELOPMENT) {
      opts.__DEVELOPMENT = true;
      console.info(
        "[auth3000] [ENV=DEVELOPMENT] Allow Insecure (localhost) Cookies"
      );
      // allow non-https cookies
      cookieDefaults.secure = false;
    }

    //
    // API Middleware & Handlers
    //
    /** @type {import('express').Handler} */
    let exchangeByIdToken = async function (req, res) {
      let jws = await verifyIdToken(req);

      //@ts-ignore
      req[opts.authnParam] = {
        strategy: "exchange",
        jws: jws,
      };
      let allClaims = await _strategyHandler(req, res);
      //@ts-ignore
      req[opts.authnParam] = null;

      // TODO deprecate
      if (allClaims || !res.headersSent) {
        let access_claims = Object.assign(
          {},
          allClaims.claims || {},
          allClaims.access_claims || {}
        );
        let jwt = await Keypairs.signJwt({
          jwk: keypair.private,
          iss: opts.issuer,
          exp: "24h",
          // optional claims
          claims: access_claims,
        });

        res.json({ access_token: jwt });
      }
    };

    /** @type {import('express').Handler} */
    let refreshByCookie = async function (req, res) {
      let jws = await verifySession(req);

      //@ts-ignore
      req[opts.authnParam] = {
        strategy: "refresh",
        jws: jws,
      };
      let allClaims = await _strategyHandler(req, res);
      //@ts-ignore
      req[opts.authnParam] = null;

      // TODO deprecate
      if (allClaims || !res.headersSent) {
        let tokens = await grantTokens(allClaims);
        res.json(tokens);
      }
    };

    /** @type {import('express').Handler} */
    let logout = async function (req, res) {
      let now = Date.now() - 10 * 60 * 1000;
      let expired = new Date(now);
      let cookieOpts = Object.assign({}, cookieDefaults, { expires: expired });
      res.cookie("refresh_token", "", cookieOpts);

      // TODO Discuss:
      // Should this ALWAYS be true? (I think so)
      // How could a logout "fail"?
      res.json({ success: true });

      // Any errors that occur here would not be meaningful to handle
      // on the client side, so we'll send success first
      if (!opts.logout) {
        return;
      }

      let jws = await verifySession(req).catch(Object);
      if (jws instanceof Error) {
        return;
      }

      //@ts-ignore
      req[opts.authnParam] = { jti: jws.claims.jti, jws };
      await opts.logout(req);
    };

    if (opts._byChallenge) {
      if (!opts.verifier) {
        //@ts-ignore
        opts.verifier = require("./verifier.js").create({
          // important
          //@ts-ignore
          notify: opts.challenge.notify || opts.notify,
          store: opts.challenge.store || opts.store,

          // optional
          coolDownMs: 250,
          idByteCount: 4,
          idEncoding: "base64",
          maxAge: opts.challenge.maxAge,
          maxAttempts: opts.challenge.maxAttempts,
          receiptByteCount: 16,
          receiptEncoding: "base64",
        });
      }
      //@ts-ignore
      if ("function" === typeof opts.verifier.setDefaults) {
        //@ts-ignore
        opts.verifier.setDefaults({
          iss: opts.issuer,
          //@ts-ignore
          secret: opts.challenge.secret || opts.secret,
          //@ts-ignore
          authnParam: opts.challenge.authnParam || opts.authnParam,
        });
      }

      let routes = require("./magic-link.js").createRouter({
        iss: opts.issuer, // TODO remove
        verifier: opts.verifier,
        DEVELOPMENT: opts.DEVELOPMENT,
        _developmentSendChallengeSecret: opts._developmentSendChallengeSecret,
        //@ts-ignore
        authnParam: opts.authnParam,
        _strategyHandler,
        grantTokensAndCookie,
      });
      app.post("/challenge/order", routes.orderVerification);
      app.get("/challenge/status", routes.checkStatus);
      app.get("/challenge", routes.checkStatus);
      app.post("/challenge/finalize", routes.redeemCode);
      //app.post("/challenge/redeem", routes.redeemCode);
      app.post("/challenge/exchange", routes.exchangeReceipt);
      //app.use("/challenge/challenge", byChallenge);
      //
    }

    // TODO pull all of these up so that the boilerplate is more clear
    if (exchangeClaims) {
      app.post("/exchange", exchangeByIdToken);
    }
    if (refreshClaims) {
      app.post("/refresh", refreshByCookie); // cookies only parsed here
    }
    app.delete("/session", logout);

    return app;
  }

  function _init() {
    if (!opts.secret && keypair.private) {
      // 'd' is the private part of both ECDSA and RSA keys
      opts.secret = keypair.private.d;
    }
    if (!opts.secret) {
      console.warn(
        "[auth3000] Warn: 'secret', which is used for cookies and authentication challenges was not given. Generating an ephemeral (temporary) secret."
      );
      opts.secret = rnd(16, "hex");
    }
    if (!opts.__INIT) {
      opts.__INIT = true;
      app.use("/", bodyParser.json({ limit: "100kb" }));
      app.use("/", function (req, res, next) {
        if (!req.ip) {
          // TODO copy the express ip middleware (w/ trust proxy et al)
          req.ip = res.socket?.remoteAddress || "";
        }
        if (!cookieDefaults.path) {
          // ex: cookieDefaults.path = "/api/authn";
          cookieDefaults.path = req.baseUrl;
        }
        next();
      });
      app.use("/", cookieParser(opts.secret)); // needed to set cookies?
      //
      // API Routes
      //
      app.use("/", function (req, res, next) {
        // TODO how to capture errors and escalate to error?

        /**@param {any} allClaims */
        res.issueRefreshCookie = async function (allClaims) {
          let tokens = await grantTokens(allClaims, req, res);
          let cookie = await grantCookie(allClaims, req);
          await resetCookie(cookie, req, res);
          res.json(tokens);
        };
        /**@param {any} allClaims */
        res.issueTokens = async function (allClaims) {
          let tokens = await grantTokens(allClaims, req, res);
          res.json(tokens);
        };
        /**@param {any} allClaims */
        res.issue = async function (allClaims) {
          //@ts-ignore
          let strategy = req[opts.authnParam]?.strategy;
          if (
            (!["jwt", "refresh", "exchange"].includes(strategy) ||
              allClaims.refresh_claims) &&
            false !== allClaims.refresh_claims
          ) {
            res.issueRefreshCookie(allClaims);
            return;
          }
          res.issueTokens(allClaims);
        };

        /**@param {any} allClaims */
        res.sign = async function (allClaims) {
          //@ts-ignore
          let strategy = req[opts.authnParam]?.strategy;
          let tokens = await grantTokens(allClaims, req, res);
          let cookie;
          if (
            (!["jwt", "refresh", "exchange"].includes(strategy) ||
              allClaims.refresh_claims) &&
            false !== allClaims.refresh_claims
          ) {
            cookie = await grantCookie(allClaims, req);
            await resetCookie(cookie, req, res);
          }
          return [tokens, cookie];
        };
        // TODO ??
        res.signTokensAndCookie = res.sign;

        /**@param {{
         *   refresh_token: String,
         *   options: any,
         * }} cookie
         * */
        res.resetCookie = async function ({ refresh_token, options }) {
          await resetCookie({ refresh_token, options }, req, res);
        };
        next();
      });
    }
  }

  let a3k = {
    challenge:
      /** @param {any} _opts // TODO */
      function (_opts) {
        // it's a verifier, not an options object
        if (_opts && _opts.setDefaults) {
          opts.verifier = _opts;
          _init();
          opts._byChallenge = true;
          return;
        }

        opts.challenge = Object.assign(opts.challenge, _opts);
        _init();

        if (!opts.challenge.store && !opts.store) {
          console.warn(
            "[auth3000] Warn: no 'store' given, falling back to in-memory (single-system only) store"
          );
          opts.store = require("./memory-store.js");
        }

        if (!opts.challenge.notify && !opts.notify) {
          console.warn(
            "[auth3000] Warn: no 'notify' given, cannot send challenges"
          );
        }

        opts._byChallenge = true;
      },
    credentials:
      /** @param {any} _opts // TODO */
      function (_opts) {
        opts = Object.assign(opts, _opts);
        _init();

        /** @type {import('express').Handler} */
        let byCredentials = async function (req, res) {
          //@ts-ignore
          req[opts.authnParam] = {
            strategy: "credentials",
          };
          let allClaims = await _strategyHandler(req, res);
          //@ts-ignore
          req[opts.authnParam] = null;

          // TODO deprecate
          if (allClaims || !res.headersSent) {
            let tokens = await grantTokens(allClaims, req, res);
            let cookie = await grantCookie(allClaims, req);
            await resetCookie(cookie, req, res);
            res.json(tokens);
          }
        };

        app.post("/session", byCredentials);
      },
    /** @param {function} _strategyHandler // TODO */
    login: function (_strategyHandler) {
      _init();
      strategyHandler = _strategyHandler;
      //throw new Error("you must provide a callback function for strategyHandler");
      if (!refreshClaims) {
        refreshClaims = strategyHandler;
      }
      if (!exchangeClaims) {
        exchangeClaims = strategyHandler;
      }
    },
    /**
     * @param {function} _refreshClaims // TODO
     */
    refresh: function (_refreshClaims) {
      _init();
      refreshClaims = _refreshClaims;
    },
    /**
     * @param {function} _exchangeClaims // TODO
     */
    exchange: function (_exchangeClaims) {
      _init();
      exchangeClaims = _exchangeClaims;
    },
    /**
     * @param {function} _logout // TODO
     */
    logout: function (_logout) {
      //@ts-ignore
      opts.logout = _logout;
    },
    oauth2:
      /** @param {any} _opts // TODO */
      function (_opts) {
        opts.oauth2 = Object.assign(opts.oauth2, _opts);
        _init();

        // TODO pick one!
        //@ts-ignore
        var _gh = opts.oauth2["github.com"] || opts.oauth2.github;
        if (_gh?.clientSecret) {
          require("./oauth2/github.com/")({
            app,
            _gh,
            opts,
            _strategyHandler,
            grantTokensAndCookie,
          });
        }
      },
    oidc:
      /**
       * @param {any} _opts // TODO
       */
      function (_opts) {
        opts.oidc = Object.assign(opts.oidc, _opts);
        _init();

        //@ts-ignore
        var _goog = opts.oidc["accounts.google.com"] || opts.oidc.google;
        if (_goog?.clientId) {
          require("./oidc/accounts.google.com/")({
            app,
            opts,
            verifyOidcToken,
            _strategyHandler,
            grantTokensAndCookie,
          });
        }
      },
    options:
      /**
       * @param {any} _opts // TODO
       */
      function (_opts) {
        opts = Object.assign(opts, _opts);
        _init();
      },
    router: router,
    wellKnown: function () {
      //
      // OIDC Well-Known Handlers
      //
      let wellKnown = require("@root/async-router").Router();
      wellKnown.get(
        "/.well-known/openid-configuration",
        async function (req, res) {
          res.json({
            iss: opts.issuer,
            jwks_uri: opts.issuer + "/.well-known/jwks.json",
          });
        }
      );
      wellKnown.get("/.well-known/jwks.json", async function (req, res) {
        res.json({ keys: [keypair.public] });
      });

      return wellKnown;
    },
  };

  // v0.10/v0.11 -> v0.12 transitional
  if ("function" === typeof myOptions) {
    a3k.login(myOptions);
    myOptions = {};
  }
  a3k.options(myOptions);

  return a3k;
};
