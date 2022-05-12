"use strict";

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

  // Only tokens signed by the expected issuer (such as https://accounts.google.com) are valid
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
let defaultRefreshMaxAge = "7d";

/**
 * @param {string} issuer
 * @param {JwsPriv} PRIVATE_KEY
 * @param {Object} myOptions
 */
module.exports = function (issuer, PRIVATE_KEY, myOptions) {
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
    DEVELOPMENT: myOptions.DEVELOPMENT,
    // assigned elsewhere
    secret: "",
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

  // Dev / Localhost Stuff
  if (opts.DEVELOPMENT) {
    console.info(
      "[libauth] [ENV=DEVELOPMENT] Allow Insecure (localhost) Cookies",
    );
    // allow non-https cookies
    cookieDefaults.secure = false;
  }

  // TODO
  /*
  if (!opts.cookiePath) {
    throw new Error(`[libauth] missing 'cookiePath'`);
  }
  cookieDefaults.path = opts.cookiePath;

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
  //*/

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
   * @param {MyAllClaims} allClaims
   */
  async function grantTokens(allClaims) {
    let id_token;
    let access_token;

    if (allClaims.claims || allClaims.id_claims) {
      let id_claims = Object.assign(
        {},
        allClaims.claims || {},
        allClaims.id_claims || {},
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
        allClaims.access_claims || {},
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
      allClaims.refresh_claims || allClaims.id_claims || {},
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
        opts._byChallenge = true;
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
      // cookies only parsed here
      /** @type {import('express').Handler} */
      async function _refreshRoutes(req, res, next) {
        let jws = await verifySession(req);

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
      async function _exchangeRoutes(req, res) {
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
            allClaims?.claims || {},
            allClaims?.access_claims || {},
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
      }

      opts._forExchange = true;
      return a3k._exchangeRoutes;
    },
    /**
     * @param {import('express').Request} req
     * @param {import('express').Response} res
     * @param {any} allClaims // TODO
     */
    grantCookie: async function (req, res, allClaims) {
      let cookie = await grantCookie(allClaims, req);
      await resetCookie(cookie, req, res);
      //return cookie;
    },
    /**
     * @param {any} allClaims // TODO
     */
    grantTokens: async function (allClaims) {
      return await grantTokens(allClaims);
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
        let now = Date.now() - 10 * 60 * 1000;
        let expired = new Date(now);
        let cookieOpts = Object.assign({}, cookieDefaults, {
          expires: expired,
        });
        // TODO set name of refresh_token
        res.cookie("refresh_token", "", cookieOpts);

        // Any errors that occur here would not be meaningful to handle
        // on the client side, so we'll send success first
        if (!opts.logout) {
          return;
        }

        let jws = await verifySession(req);

        //@ts-ignore
        req[opts.authnParam] = {
          stategy: "logout",
          jti: jws.claims.jti,
          jws,
        };

        if (next) {
          next();
        }
        //return req[opts.authnParam];
      }

      return _logoutRoutes;
    },
    /** @param {any} _opts // TODO */
    oauth2: function (_opts) {
      opts.oauth2 = Object.assign(opts.oauth2, _opts);

      let _oauth2Routes = {
        "github.com": function (req, res, next) {},
      };

      // TODO pick one!
      //@ts-ignore
      var _gh = opts.oauth2["github.com"] || opts.oauth2.github;
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
      let _goog = opts.oidc[_issuerName] || opts.oidc.google;
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
    /*
    _oauth2Routes: {
      ///@type {import('express').Handler}
      "github.com": function () {},
    },
    */
    secureCompare: Util.secureCompare,
    /** @param {import('express').Request} req */
    _isNewSession: function (req) {
      //return !["refresh", "exchange", "logout"].includes(req[].strategy)
      return ["credentials", "challenge", "oidc", "oauth2", "oauth"].includes(
        ///@ts-ignore
        req[opts.authnParam].strategy,
      );
    },
    //@ts-ignore
    grantCookieIfNewSession: async function (req, res, allClaims) {
      if (a3k._isNewSession(req)) {
        await a3k.grantCookie(req, res, allClaims);
      }
    },
  };

  Object.assign(opts, myOptions);

  return a3k;
};

module.exports.create = module.exports;
