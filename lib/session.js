"use strict";

let LibAuth = exports;

let FsSync = require("fs");

let bodyParser = require("body-parser");
let cookieParser = require("cookie-parser");

// JWT Stuff
//@ts-ignore
let Keyfetch = require("keyfetch");
// TODO update to @root/keypairs
//@ts-ignore
let Keypairs = require("keypairs");

let Util = require("./util.js");

//
// Helper functions
//
let E = require("./errors.js");
let rnd = require("./rnd.js");
let parseDuration = require("./parse-duration.js");

/**
 * //TODO move this JSDoc to keypairs
 * @typedef {Object} Keypair
 * @property {JwsPriv} private
 * @property {JwsPub} public
 */

/**
 * @param {JwsPriv} PRIVATE_KEY
 * @param {Keypair} keypair
 * @returns JwsPub
 */
function parsePrivateKey(PRIVATE_KEY, keypair) {
  keypair.private = PRIVATE_KEY;

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
      }),
    );
  }

  if (!keypair.public.kid) {
    // Thumbprint a JWK (SHA256)
    Keypairs.thumbprint({ jwk: keypair.private })
      //@ts-ignore
      .then(function (thumb) {
        keypair.public.kid = thumb;
      })
      //@ts-ignore
      .catch(function (err) {
        console.error("[libauth] Error parsePrivateKey:", err);
      });
  }

  return keypair.public;
}

/**
 * @param {OidcVerifyOpts} verifyOpts
 * @param {tokenVerifier} tokenVerifier
 * @returns {import('express').Handler}
 */
function verifyOidcToken(verifyOpts, tokenVerifier) {
  if (!tokenVerifier) {
    tokenVerifier = async function (jws) {};
  }

  // Only tokens signed by the expected issuer
  // (such as https://accounts.google.com) are valid
  /** @type {import('express').Handler} */
  function _verifyOidc(req, res, next) {
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
              `unexpectedly passed issuer validation: '${decoded.claims.iss}' does not match '${verifyOpts.iss}'`,
            );
          }
          await tokenVerifier(decoded);
          // just in case
          if (decoded.claims.email) {
            decoded.claims.email = decoded.claims.email.toLowerCase();
          }

          // "jws" is the technical term for a decoded "jwt"
          //@ts-ignore
          req._jws = decoded;
          next();
        },
      )
      .catch(next);
  }

  return _verifyOidc;
}

let defaultIdMaxAge = "24h";
let defaultAccessMaxAge = "1h";
let defaultRefreshMaxAge = "1d";
let defaultTrustedMaxAge = "7d";

/**
 * @param {string} issuer
 * @param {JwsPriv} PRIVATE_KEY
 * @param {Object} myOptions
 * @param {String} myOptions.cookiePath
 * @param {Boolean} myOptions.DEVELOPMENT
 */
LibAuth.create = function (issuer, PRIVATE_KEY, myOptions) {
  let opts = {
    issuer: issuer,
    oidc: {},
    challenge: {
      idByteCount: 4,
      /** @type {import('crypto').BinaryToTextEncoding} */
      idEncoding: "base64",
      maxAge: "24h",
      maxAttempts: 5,
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
    /** @type {import('./memory-store.js').MemoryStore} */
    //@ts-ignore
    store: null,
    challengeMaxAge: 0,
    challengeMaxAttempts: 0,
    authnParam: "authn",
    cookiePath: myOptions.cookiePath,
    DEVELOPMENT: myOptions.DEVELOPMENT,
    // assigned elsewhere
    secret: "",
  };

  // Cookie Stuff
  // See https://github.com/BeyondCodeBootcamp/beyondcodebootcamp.com/blob/main/articles/express-cookies-cheatsheet.md
  /** @type {import('express').CookieOptions} */
  let cookieDefaults = {
    signed: true,
    path: opts.cookiePath,
    httpOnly: true,
    sameSite: "strict",
    secure: true,
    //expires: 0, // should be set on each issuance
  };
  if (!cookieDefaults.path) {
    throw new Error(`[libauth] missing 'opts.cookiePath'`);
  }
  if (!cookieDefaults.path.startsWith("/")) {
    throw new Error(
      `[libauth] 'opts.cookiePath' should start with leading '/'`,
    );
  }
  if (!cookieDefaults.path.endsWith("/")) {
    throw new Error(`[libauth] 'opts.cookiePath' should end with trailing '/'`);
  }
  if (cookieDefaults.path.length < 3) {
    throw new Error(
      `[libauth] 'opts.cookiePath' should be scoped to a path, such as '/api/authn/'`,
    );
  }

  // Dev / Localhost Stuff
  if (opts.DEVELOPMENT) {
    console.info(
      "[libauth] [ENV=DEVELOPMENT] Allow Insecure (localhost) Cookies",
    );
    // allow non-https cookies
    cookieDefaults.secure = false;
  }

  /*
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
  */

  // it is possible that this _might_ not happen until a millisecond
  // or two _after_ the server is accepting connections
  // See https://github.com/therootcompany/libauth/issues/8
  /** @type {Keypair} */
  //@ts-ignore
  let keypair = {};
  if (!PRIVATE_KEY || !PRIVATE_KEY.d) {
    throw new Error(
      "[libauth] Private Key is not a JWK object." +
        "\n          Use @root/keypairs to parse PEM as JWK or generate new JWKs",
    );
  }

  // really more to get public key
  //@ts-ignore
  parsePrivateKey(PRIVATE_KEY, keypair);

  if (!opts.secret) {
    // 'd' is the private part of both ECDSA and RSA keys
    opts.secret = keypair.private.d;
  }
  if (!opts.secret) {
    console.warn(
      "[libauth] Warn: 'secret', which is used for cookies and authentication challenges was not given. Generating an ephemeral (temporary) secret.",
    );
    opts.secret = rnd(16, "hex");
  }

  /**
   * @param {String} refreshToken
   * @param {any} _opts
   */
  async function verifyToken(refreshToken, _opts) {
    return Keyfetch.jwt.verify(
      refreshToken,
      Object.assign(
        {
          iss: opts.issuer,
        },
        _opts,
      ),
    );
  }

  /**
   * @param {import('express').Request} req
   */
  async function verifyIdToken(req) {
    let jwt = (req.headers.authorization || "").replace("Bearer ", "");
    let jws = await verifyJwt(jwt);
    return jws;
  }

  /**
   * @param {string} jwt
   * @returns {Promise<Jws>}
   */
  async function verifyJwt(jwt) {
    let jws = await Keyfetch.jwt.verify(jwt, {
      issuers: [opts.issuer], // or ['*']
      // TODO force only one public key?
      jwk: keypair.public,
    });

    return jws;
  }

  /*
    if (a3k._oauth2Routes["github.com"]) {
      app.post("/session/oauth2/github.com", a3k._oauth2Routes["github.com"]);
    }
  */

  let a3k = {
    /** @param {any} _opts // TODO */
    challenge: function (_opts) {
      // it's a verifier, not an options object
      if (_opts && _opts.setDefaults) {
        opts.verifier = _opts;
        return;
      }

      opts.challenge = Object.assign(opts.challenge, _opts);

      if (!opts.challenge.store && !opts.store) {
        console.warn(
          "[libauth] Warn: no 'store' given, falling back to in-memory (single-system only) store",
        );
        opts.store = require("./memory-store.js");
      }

      if (!opts.verifier) {
        //@ts-ignore
        opts.verifier = require("./verifier.js").create({
          // important
          //@ts-ignore
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

      let _challengeRoutes = require("./magic-link.js").createRouter({
        iss: opts.issuer,
        verifier: opts.verifier,
        //@ts-ignore
        authnParam: opts.authnParam,
      });

      return _challengeRoutes;
    },

    /** @param {any} _opts // TODO */
    credentials: function (_opts) {
      opts = Object.assign(opts, _opts);

      /** @type {import('express').Handler} */
      async function _credentialRoutes(req, res, next) {
        let creds;

        let authBasic = req.headers["authorization"] || "";
        if (false !== _opts?.basic && authBasic.startsWith("Basic ")) {
          creds = Util.decodeAuthorizationBasic(req);
        }

        if (!creds?.username) {
          let userKey = _opts?.username || _opts?.user || "username";
          let passKey = _opts?.password || _opts?.pass || "password";
          creds = {
            username: req.body[userKey],
            password: req.body[passKey],
          };
        }

        let authn = {
          strategy: "credentials",
          username: creds.username,
          password: creds.password,
          valid: false,
        };

        //@ts-ignore
        req[opts.authnParam] = authn;
        next();
      }

      return _credentialRoutes;
    },

    refresh: function () {
      /** @type {import('express').Handler} */
      async function _refreshRoutes(req, res, next) {
        let refreshToken = req.signedCookies.refresh_token;
        if (!refreshToken) {
          throw E.SESSION_INVALID();
        }

        let jws = await verifyToken(refreshToken, null);

        //@ts-ignore
        req[opts.authnParam] = {
          strategy: "refresh",
          jws: jws,
        };

        next();
      }

      return _refreshRoutes;
    },

    exchange: function () {
      /** @type {import('express').Handler} */
      async function _exchangeRoutes(req, res, next) {
        let jws = await verifyIdToken(req);

        //@ts-ignore
        req[opts.authnParam] = {
          strategy: "exchange",
          jws: jws,
          _claimOptions: {
            exp: "24h",
          },
        };

        next();
      }

      return _exchangeRoutes;
    },

    /**
     * @param {import('express').Request} req
     * @param {import('express').Response} res
     * @param {MyAccessClaims} refreshClaims
     */
    _setCookie: async function (req, res, refreshClaims) {
      let previousToken = req.signedCookies?.refresh_token;

      let maxAge = refreshClaims.exp;
      if (!maxAge) {
        if (req.body?.trust_device) {
          maxAge = defaultTrustedMaxAge;
        } else {
          maxAge = defaultRefreshMaxAge;
        }
      }
      refreshClaims.exp = maxAge;

      let refreshToken = await a3k.issueRefreshToken(refreshClaims);
      let cookieOpts = Object.assign({}, cookieDefaults, {
        maxAge: parseDuration(maxAge),
      });

      let oldJws;

      // expire the old cookie in the db
      if (previousToken) {
        oldJws = await verifyToken(previousToken, null).catch(function () {
          // ignore invalid token
        });
      }

      res.cookie("refresh_token", refreshToken, cookieOpts);

      return oldJws || null;
    },

    /**
     * @param {function} _logout // TODO
     */
    logout: function (_logout) {
      // TODO set cookie options?
      //@ts-ignore
      opts.logout = _logout;

      /** @type {import('express').Handler} */
      async function _logoutRoutes(req, res, next) {
        let previousToken = req.signedCookies.refresh_token;

        a3k._clearCookie(res);

        //@ts-ignore
        req[opts.authnParam] = { stategy: "logout", oldJws: null };

        // TODO catch no token error?
        if (previousToken) {
          let oldJws = await verifyToken(previousToken, null).catch(
            function () {
              // ignore invalid token
            },
          );

          if (oldJws) {
            //@ts-ignore
            req[opts.authnParam].oldJws = oldJws;
          }
        }

        next();
      }

      return _logoutRoutes;
    },
    /**
     * @param {import('express').Response} res
     */
    _clearCookie: function (res) {
      let now = Date.now() - 10 * 60 * 1000;
      let expired = new Date(now);
      let cookieOpts = Object.assign({}, cookieDefaults, {
        expires: expired,
      });
      // TODO set name of refresh_token
      res.cookie("refresh_token", "", cookieOpts);
    },

    /** @param {any} _opts // TODO */
    oauth2: function (_opts) {
      opts.oauth2 = Object.assign(opts.oauth2, _opts);

      let _oauth2Routes = {
        /** @type {import('express').Handler} */
        "github.com": function (req, res, next) {},
      };

      // TODO pick one!
      //@ts-ignore
      var _gh = opts.oauth2["github.com"];
      if (_gh?.clientSecret) {
        let ghRoutes = require("./oauth2/github.com/").create({
          _gh,
          opts,
        });
        _oauth2Routes["github.com"] = ghRoutes;
      }

      return _oauth2Routes;
    },

    /**
     * @param {any} _opts // TODO
     */
    oidc: function (_opts) {
      opts.oidc = Object.assign(opts.oidc, _opts);

      let _issuerName = "accounts.google.com";
      /// @ts-ignore
      let _oidcRoutes = {};

      //@ts-ignore
      let _goog = opts.oidc[_issuerName];
      if (_goog?.clientId) {
        let googRoutes = require("./oidc/accounts.google.com/").create({
          opts,
          verifyOidcToken,
          _issuerName,
        });
        /// @ts-ignore
        _oidcRoutes[_issuerName] = googRoutes;
      }

      // TODO this should return one route per strategy??
      return _oidcRoutes;
    },

    /*
    _oauth2Routes: {
      ///@type {import('express').Handler}
      "github.com": function () {},
    },
    */

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
        },
      );
      wellKnown.get("/.well-known/jwks.json", async function (req, res) {
        res.json({ keys: [keypair.public] });
      });

      return wellKnown;
    },

    /**
     * @param {MyAccessClaims | MyIdClaims} claims
     * @param {String | Number} maxAge
     */
    issueToken: async function (claims, maxAge) {
      return await Keypairs.signJwt({
        jwk: keypair.private,
        iss: opts.issuer,
        exp: claims.exp || maxAge,
        claims: claims,
      });
    },

    /**
     * @param {MyAccessClaims} refreshClaims
     */
    issueRefreshToken: async function (refreshClaims) {
      return await a3k.issueToken(refreshClaims, defaultRefreshMaxAge);
    },

    /**
     * @param {MyIdClaims} idClaims
     */
    issueIdToken: async function (idClaims) {
      return await a3k.issueToken(idClaims, defaultIdMaxAge);
    },

    /**
     * @param {MyAccessClaims} accessClaims
     */
    issueAccessToken: async function (accessClaims) {
      return await a3k.issueToken(accessClaims, defaultAccessMaxAge);
    },

    secureCompare: Util.secureCompare,
    /** @param {import('express').Request} req */
    _isNewSession: function (req) {
      //return !["refresh", "exchange", "logout"].includes(req[].strategy)
      return ["credentials", "challenge", "oidc", "oauth2", "oauth"].includes(
        ///@ts-ignore
        req[opts.authnParam].strategy,
      );
    },

    /**
     * @param {import('express').Request} req
     * @param {import('express').Response} res
     * @param {MyAccessClaims} refreshClaims
     */
    setCookieIfNewSession: async function (req, res, refreshClaims) {
      if (a3k._isNewSession(req)) {
        return await a3k._setCookie(req, res, refreshClaims);
      }
      return null;
    },
  };

  Object.assign(opts, myOptions);

  return a3k;
};
