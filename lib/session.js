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

let defaultIdMaxAge = "24h";
let defaultAccessMaxAge = "1h";
let defaultRefreshMaxAge = "1d";
let defaultTrustedMaxAge = "7d";

/**
 * @param {string} issuer
 * @param {JwsPriv} PRIVATE_KEY
 * @param {Object} myOptions
 * @param {String} myOptions.cookiePath
 */
LibAuth.create = function (issuer, PRIVATE_KEY, myOptions) {
  let opts = {
    issuer: issuer,
    oidc: {},
    credentials: {
      basic: true,
      username: "username",
      password: "password",
    },
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
    // assigned elsewhere
    secret: "",
    loginUrl: "",
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
    if (libauth._oauth2Routes["github.com"]) {
      app.post("/session/oauth2/github.com", libauth._oauth2Routes["github.com"]);
    }
  */

  function _initialize() {
    /** @type {import('express').Handler} */
    return function (req, res, next) {
      /** @type any */
      let jwt;
      /** @type any */
      let jws;
      //@ts-ignore
      req.__libauth = {
        /**
         * @param {any} _jwt
         */
        jwt: function (_jwt) {
          if (_jwt) {
            jwt = _jwt;
          }
          return jwt;
        },
        /**
         * @param {any} _jws
         */
        jws: function (_jws) {
          if (_jws) {
            jws = _jws;
          }
          return jwt;
        },
      };
    };
  }

  /** @param {any} _opts // TODO */
  function _credentials(_opts) {
    let credOpts = Object.assign(opts.credentials, _opts);

    /** @type {import('express').Handler} */
    async function _credentialRoutes(req, res, next) {
      let creds;

      let authBasic = req.headers["authorization"] || "";
      if (false !== credOpts.basic && authBasic.startsWith("Basic ")) {
        creds = Util.decodeAuthorizationBasic(req);
      }

      if (!creds?.username) {
        let userKey = credOpts.username || "username";
        let passKey = credOpts.password || "password";
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
  }

  function _refresh() {
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
  }

  function _exchange() {
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
  }

  /**
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @param {MyAccessClaims} refreshClaims
   */
  async function _setCookie(req, res, refreshClaims) {
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

    let refreshToken = await libauth.issueRefreshToken(refreshClaims);
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
  }

  /**
   * @param {function} _logoutFn // TODO
   */
  function _logout(_logoutFn) {
    // TODO set cookie options?
    //@ts-ignore
    opts.logout = _logoutFn;

    /** @type {import('express').Handler} */
    async function _logoutRoutes(req, res, next) {
      let previousToken = req.signedCookies.refresh_token;

      libauth._clearCookie(res);

      //@ts-ignore
      req[opts.authnParam] = { stategy: "logout", oldJws: null };

      // TODO catch no token error?
      if (previousToken) {
        let oldJws = await verifyToken(previousToken, null).catch(function () {
          // ignore invalid token
        });

        if (oldJws) {
          //@ts-ignore
          req[opts.authnParam].oldJws = oldJws;
        }
      }

      next();
    }

    return _logoutRoutes;
  }

  /**
   * @param {import('express').Response} res
   */
  function _clearCookie(res) {
    let now = Date.now() - 10 * 60 * 1000;
    let expired = new Date(now);
    let cookieOpts = Object.assign({}, cookieDefaults, {
      expires: expired,
    });
    // TODO set name of refresh_token
    res.cookie("refresh_token", "", cookieOpts);
  }

  /** @param {any} _opts // TODO */
  function _oauth2(_opts) {
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
  }

  function _wellKnown() {
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
  }

  /**
   * @param {MyAccessClaims | MyIdClaims} claims
   * @param {String | Number} maxAge
   */
  async function _issueToken(claims, maxAge) {
    return await Keypairs.signJwt({
      jwk: keypair.private,
      iss: opts.issuer,
      exp: claims.exp || maxAge,
      claims: claims,
    });
  }

  /**
   * @param {MyAccessClaims} refreshClaims
   */
  async function _issueRefreshToken(refreshClaims) {
    return await libauth.issueToken(refreshClaims, defaultRefreshMaxAge);
  }

  /**
   * @param {MyIdClaims} idClaims
   */
  async function _issueIdToken(idClaims) {
    return await libauth.issueToken(idClaims, defaultIdMaxAge);
  }

  /**
   * @param {MyAccessClaims} accessClaims
   */
  async function _issueAccessToken(accessClaims) {
    return await libauth.issueToken(accessClaims, defaultAccessMaxAge);
  }

  /**
   * @param {import('express').Request} req
   */
  function _isNewSession(req) {
    //return !["refresh", "exchange", "logout"].includes(req[].strategy)
    return ["credentials", "challenge", "oidc", "oauth2", "oauth"].includes(
      ///@ts-ignore
      req[opts.authnParam].strategy,
    );
  }

  /**
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @param {MyAccessClaims} refreshClaims
   */
  async function _setCookieIfNewSession(req, res, refreshClaims) {
    if (libauth._isNewSession(req)) {
      return await libauth._setCookie(req, res, refreshClaims);
    }
    return null;
  }

  /**
   * Verifies a 3rd-Party Token
   * @param {any} jwt
   * @param {OidcVerifyOpts} verifyOpts
   */
  async function _oidcVerifyToken(jwt, verifyOpts) {
    // JWS is the technical term for a decoded JWT
    let jws = await Keyfetch.jwt.verify(jwt, verifyOpts);

    if ("function" === typeof verifyOpts.pluginVerify) {
      verifyOpts.pluginVerify(jws);
    }

    if (false !== verifyOpts.iss) {
      // a failsafe for older versions of keyfetch with ['*'] by default
      if (jws.claims.iss != verifyOpts.iss) {
        throw new Error(
          `unexpectedly passed issuer validation: '${jws.claims.iss}' does not match '${verifyOpts.iss}'`,
        );
      }
    }

    if (jws.claims.email) {
      // lowercase, just in case
      jws.claims.email = jws.claims.email.toLowerCase();
      // check email_verified, just in case
      if (false !== verifyOpts.email_verified && !jws.claims.email_verified) {
        throw E.OIDC_UNVERIFIED_IDENTIFIER("email");
      }
    }

    return jws;
  }

  /**
   * @param {String} trustedUrl - the base URL that we trust
   * @param {String} untrustedUrl - the redirect URL
   * @returns {Boolean}
   */
  function prefixesUrl(trustedUrl, untrustedUrl) {
    if ("/" !== untrustedUrl[untrustedUrl.length - 1]) {
      untrustedUrl = `${untrustedUrl}/`;
    }

    // TODO throw instead of false?
    return untrustedUrl.startsWith(trustedUrl);
  }

  /**
   * @param {any} pluginOpts
   */
  function _oidc(pluginOpts) {
    let oidcOpts = Object.assign({}, pluginOpts);

    var crypto = require("crypto");

    // TODO initialize and require from ./lib/request.js
    //@ts-ignore
    let request = require("@root/request");

    let OIDC = require("./oidc.js");

    /** @param {String|Buffer|Array<any>} val */
    function toUrlBase64(val) {
      return Buffer.from(val)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
    }

    /** @type {import('express').Handler} */
    function authorizationRedirect(req, res, next) {
      async function _authorizationRedirect() {
        if (req.query.code || req.query.error) {
          next();
          return;
        }

        //let oidcAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth";
        let oidcConfig = await OIDC.getConfig(pluginOpts.iss);

        // ex: https://app.example.com/api/authn/session/oidc/accounts.google.com/redirect
        let selfUrl = req.originalUrl || req.url;
        selfUrl = new URL(`https://example.com${selfUrl}`).pathname;
        //selfUrl = `${opts.issuer}${selfUrl}`;
        selfUrl = `${opts.issuer}${selfUrl}`;

        let state = crypto.randomInt(Math.pow(2, 32) - 1).toString(16);

        /* { clientId, scope } */
        let query = Object.assign(pluginOpts.authorizationQuery, req.query, {
          redirect_uri: selfUrl,
          state: state,
          response_type: "code",
        });

        let url = OIDC.generateOidcUrl(
          oidcConfig.authorization_endpoint,
          query,
        );

        //@ts-ignore
        req[opts.authnParam] = {
          strategy: "oidc_authorization",
          redirect_status: 302,
          redirect_uri: url.toString(),
        };

        // TODO XXXX hand control back?
        // "Found" (a.k.a. temporary redirect)
        res.redirect(
          //@ts-ignore
          req[opts.authnParam].redirect_status,
          //@ts-ignore
          req[opts.authnParam].redirect_uri,
        );
      }

      //@ts-ignore
      return Promise.resolve().then(_authorizationRedirect).catch(next);
    }

    /** @type {import('express').Handler} */
    function exchangeCode(req, res, next) {
      async function _exchangeCode() {
        let oidcConfig = await OIDC.getConfig(pluginOpts.iss);
        let clientId = pluginOpts.clientId;
        let clientSecret = pluginOpts.clientSecret;
        let code = req.query.code;

        if (!pluginOpts.redirectUri) {
          let ownPath = req.originalUrl || req.url;
          ownPath = new URL(`https://example.com${ownPath}`).pathname;
          let issuer = opts.issuer;
          if (issuer.endsWith("/")) {
            issuer = issuer.slice(0, -1);
          }
          pluginOpts.redirectUri = `${issuer}${ownPath}`;
        }

        let form = {
          client_id: clientId,
          client_secret: clientSecret,
          code: code,
          grant_type: "authorization_code",
          redirect_uri: pluginOpts.redirectUri,
        };

        let resp = await request({
          method: "POST",
          url: oidcConfig.token_endpoint,
          // www-urlencoded...
          json: true,
          form: form,
        });

        //@ts-ignore
        if (!req[opts.authnParam]) {
          //@ts-ignore
          req[opts.authnParam] = {};
        }
        //@ts-ignore
        req[opts.authnParam] = Object.assign(req[opts.authnParam], resp.body, {
          strategy: "oidc_code",
          request: form,
        });

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(_exchangeCode).catch(next);
    }

    /** @type {import('express').Handler} */
    function exchangeToken(req, res, next) {
      async function _exchangeToken() {
        // TODO pick just authorization? Always add it in exchangeCode?
        let jwt = (req.headers.authorization || "").replace(/^Bearer /, "");
        if (!jwt) {
          //@ts-ignore
          jwt =
            req[opts.authnParam]?.id_token ||
            req[opts.authnParam]?.access_token;
        } else {
          //req.headers.authorization = `Bearer ${token}`;
        }
        let jws = await _oidcVerifyToken(jwt, oidcOpts);

        //@ts-ignore
        if (!req[opts.authnParam]) {
          //@ts-ignore
          req[opts.authnParam] = {};
        }
        //@ts-ignore
        req[opts.authnParam] = Object.assign(req[opts.authnParam], {
          strategy: "oidc",
          //@ts-ignore
          email: jws.claims.email,
          //@ts-ignore
          iss: jws.claims.iss,
          //@ts-ignore
          ppid: jws.claims.sub,
          //@ts-ignore
          oidc_header: jws.header,
          //@ts-ignore
          oidc_claims: jws.claims,
        });

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(_exchangeToken).catch(next);
    }

    return {
      // TODO make sure we're using the standard names
      authorizationRedirect,
      exchangeCode,
      exchangeToken,
    };
  }

  let libauth = {
    // init
    initialize: _initialize,

    // token-token
    refresh: _refresh,
    exchange: _exchange,

    // remove auth
    logout: _logout,
    _clearCookie: _clearCookie,

    // replace auth
    credentials: _credentials,
    _setCookie: _setCookie,
    oidc: _oidc,
    oauth2: _oauth2,

    // helpers
    issueToken: _issueToken,
    issueRefreshToken: _issueRefreshToken,
    issueIdToken: _issueIdToken,
    issueAccessToken: _issueAccessToken,
    setCookieIfNewSession: _setCookieIfNewSession,
    _isNewSession: _isNewSession,

    // other helpers
    secureCompare: Util.secureCompare,

    // for verification
    wellKnown: _wellKnown,
  };

  /** @param {any} _opts // TODO */
  //@ts-ignore
  libauth.challenge = require("./magic.js").create(libauth, opts);

  Object.assign(opts, myOptions);

  return libauth;
};
