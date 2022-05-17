"use strict";

let LibAuth = exports;

let Crypto = require("crypto");

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
 * @param {string} issuer
 * @param {JwsPriv} PRIVATE_KEY
 * @param {Object} myOptions
 * @param {String} myOptions.idMaxAge
 * @param {String} myOptions.accessMaxAge
 * @param {String} myOptions.sessionMaxAge
 * @param {String} myOptions.refreshMaxAge
 * @param {String} myOptions.cookiePath
 * @param {String} myOptions.cookieName
 * @param {String} myOptions.propName
 */
LibAuth.create = function (issuer, PRIVATE_KEY, myOptions) {
  // TODO set as part of creation
  // { idClaims: { exp: '24h' }

  let libOpts = {
    issuer: issuer,
    sessionMaxAge: myOptions.sessionMaxAge || "12h",
    trustedMaxAge: "", // TODO
    idMaxAge: myOptions.idMaxAge || "24h",
    accessMaxAge: myOptions.accessMaxAge || "1h",
    refreshMaxAge: myOptions.refreshMaxAge || "7d",
    authnParam: myOptions.propName || "libauth",
    cookieName: myOptions.cookieName || "session_token",
    cookiePath: myOptions.cookiePath || "/api/session/",
  };

  // Cookie Stuff
  // See https://github.com/BeyondCodeBootcamp/beyondcodebootcamp.com/blob/main/articles/express-cookies-cheatsheet.md
  /** @type {import('express').CookieOptions} */
  let cookieDefaults = {
    signed: true,
    path: libOpts.cookiePath,
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
      `[libauth] 'opts.cookiePath' should be scoped to a path, such as '/api/session/'`,
    );
  }

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

  /**
   * @param {import('express').Request} req
   */
  async function verifySessionJwt(req) {
    let previousToken;
    if (req.signedCookies) {
      previousToken = req.signedCookies[libOpts.cookieName];
    }
    if (!previousToken) {
      // TODO or throw error?
      return;
    }

    let sessionJws = await verifyJwt(previousToken);
    return sessionJws;
  }

  /**
   * @param {import('express').Request} req
   */
  async function verifyBearerJwt(req) {
    let jwt = (req.headers.authorization || "").replace("Bearer ", "");
    let jws = await verifyJwt(jwt);
    return jws;
  }

  /**
   * @param {string} jwt
   * @returns {Promise<Jws>}
   */
  async function verifyJwt(jwt) {
    let verifyOpts = {
      issuers: [libOpts.issuer], // or ['*']
      // TODO force only one public key?
      jwk: keypair.public,
    };
    let jws = await Keyfetch.jwt.verify(jwt, verifyOpts);
    return jws;
  }

  function _initialize() {
    /** @type {import('express').Handler} */
    return function (req, res, next) {
      libauth._init(req);
      next();
    };
  }

  /** @param {import('express').Request} req */
  function _init(req) {
    //@ts-ignore
    if (req[libauthKey]) {
      return;
    }

    /** @type Record<String,any> */
    let cache = {};
    //@ts-ignore
    req[libauthKey] = {
      /** @param {String} k */
      get: function (k) {
        return cache[k];
      },
      /**
       * @param {String} k
       * @param {any} v
       * */
      set: function (k, v) {
        cache[k] = v;
      },
    };
  }

  /**
   * @param {import('express').Request} req
   * @param {String|any} key
   * @param {any} [value]
   */
  function _set(req, key, value) {
    libauth._init(req);

    if ("object" !== typeof key) {
      //@ts-ignore
      req[libauthKey].set(key, value);
      return;
    }

    // libauth.set(req, { foo: 'bar', baz: 'quux' })
    Object.keys(key).forEach(function (k) {
      ///@ts-ignore
      req[libauthKey].set(k, key[k]);
    });
  }

  /**
   * @param {import('express').Request} req
   * @param {String} key
   */
  function _get(req, key) {
    libauth._init(req);
    //@ts-ignore
    return req[libauthKey].get(key);
  }

  //
  // Routes
  //

  /**
   * @param {any} _credOpts // TODO
   * @returns {import('express').Handler}
   */
  function _credentials(_credOpts) {
    let credOpts = Object.assign(
      {},
      {
        basic: true,
        username: "username",
        password: "password",
      },
      _credOpts || {},
    );

    /** @type {import('express').Handler} */
    return function (req, res, next) {
      async function mw() {
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

        libauth.set(req, {
          strategy: "credentials",
          username: creds.username,
          password: creds.password,
          valid: false,
        });

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    };
  }

  /**
   * @returns {import('express').Handler}
   */
  function _refresh() {
    return function _refreshRoutes(req, res, next) {
      async function mw() {
        let sessionJws = await verifySessionJwt(req);
        if (!sessionJws) {
          throw E.SESSION_INVALID();
        }
        let sessionClaims = sessionJws.claims;

        libauth.set(req, {
          strategy: "refresh",
          sessionClaims: sessionJws.claims,
          user: {
            issuer: sessionJws.claims.iss,
            id: sessionJws.claims.sub,
            email: sessionJws.claims.email,
          },
        });

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    };
  }

  /**
   * @returns {import('express').Handler}
   */
  function _exchange() {
    return function _exchangeRoutes(req, res, next) {
      async function mw() {
        let bearerJws = await verifyBearerJwt(req);
        let bearerClaims = bearerJws.claims;

        libauth.set(req, {
          strategy: "exchange",
          bearerJws,
          bearerClaims,
          user: {
            issuer: bearerClaims.iss,
            id: bearerClaims.sub,
            email: bearerClaims.email,
          },
        });

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    };
  }

  /**
   * @returns {import('express').Handler}
   */
  function _newSession() {
    return function newSession(req, res, next) {
      libauth.set(req, "newSession", true);
      libauth.set(req, "sessionClaims", {});
      next();
    };
  }

  /**
   * @returns {import('express').Handler}
   */
  function _setClaims() {
    return function setClaims(req, res, next) {
      async function mw() {
        let sessionJws;
        let authTime;
        let jti;
        let sub;
        if (!libauth.get(req, "newSession")) {
          sessionJws = libauth.get(req, "sessionJws");
        }
        if (sessionJws.claims) {
          authTime = sessionJws.claims.auth_time;
          jti = sessionJws.claims.jti;
          sub = sessionJws.claims.sub;
        }
        if (!sub) {
          throw E.DEVELOPER_ERROR(
            "'sub' must be set as the user id by middleware, or the existing session token",
          );
        }
        if (!authTime) {
          authTime = Math.round(Date.now() / 1000);
        }
        if (!jti) {
          jti = rnd(16, "base64");
        }

        let baseClaims = {
          jti: jti,
          iss: libOpts.issuer,
          sub: sub,
          auth_time: authTime,
        };

        _setIdClaims(req, baseClaims);
        _setAccessClaims(req, baseClaims);
        _setRefreshClaims(req, baseClaims);
        _setSessionClaims(req, baseClaims);

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    };
  }

  /**
   * Same as access, but longer max age
   * @param {import('express').Request} req
   * @param {any} baseClaims
   */
  function _setIdClaims(req, baseClaims) {
    let idClaims = libauth.get(req, "idClaims");
    if (!idClaims) {
      return;
    }
    /*
      if (!("iss" in idClaims)) {
        idClaims.iss = libOpts.issuer;
      }
      if (!("jti" in idClaims)) {
        idClaims.jti = jti;
      }
      if (!("exp" in idClaims)) {
        idClaims.exp = libOpts.idMaxAge;
      }
      if (!("auth_time" in idClaims)) {
        idClaims.auth_time = authTime;
      }
    */

    idClaims = Object.assign(
      {},
      baseClaims,
      {
        exp: libOpts.idMaxAge,
      },
      idClaims,
    );
    libauth.set(req, "idClaims", idClaims);
  }

  /**
   * Same as access, but longer max age
   * @param {import('express').Request} req
   * @param {any} baseClaims
   */
  function _setAccessClaims(req, baseClaims) {
    let accessClaims = libauth.get(req, "accessClaims");
    if (!accessClaims) {
      return;
    }

    accessClaims = Object.assign(
      {},
      baseClaims,
      {
        exp: libOpts.accessMaxAge,
      },
      accessClaims,
    );
    libauth.set(req, "accessClaims", accessClaims);
  }

  /**
   * Same as access, but longer max age
   * @param {import('express').Request} req
   * @param {any} baseClaims
   */
  function _setRefreshClaims(req, baseClaims) {
    let refreshClaims = libauth.get(req, "refreshClaims");
    if (!refreshClaims) {
      return;
    }

    refreshClaims = Object.assign(
      {},
      baseClaims,
      {
        exp: libOpts.refreshMaxAge,
      },
      refreshClaims,
    );
    libauth.set(req, "refreshClaims", refreshClaims);
  }

  /**
   * Same as refresh, but shorter default max age
   * @param {import('express').Request} req
   * @param {any} baseClaims
   */
  function _setSessionClaims(req, baseClaims) {
    let sessionClaims = libauth.get(req, "sessionClaims");
    if (!sessionClaims) {
      return;
    }

    let sessionMaxAge = libOpts.sessionMaxAge;
    // TODO is this really the best place for trust_device?
    if (req.body.trust_device) {
      sessionMaxAge = libOpts.trustedMaxAge || libOpts.refreshMaxAge;
    }
    sessionClaims = Object.assign(
      {},
      baseClaims,
      {
        exp: sessionMaxAge,
      },
      sessionClaims,
    );
    libauth.set(req, "sessionClaims", sessionClaims);
  }

  /**
   * @returns {import('express').Handler}
   */
  function _setCookie() {
    return function setCookie(req, res, next) {
      async function mw() {
        // Make previous session available, if any
        let previousJws = await verifySessionJwt(req).catch(function (err) {
          libauth.set(req, "sessionError", err);
        });
        if (previousJws) {
          libauth.set(req, { sessionJws: previousJws });
        }

        // Generate new session
        let sessionClaims = libauth.get(req, "sessionClaims");
        let sessionToken = await libauth.issueToken(sessionClaims);

        libauth.set(req, "sessionToken", sessionToken);

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    };
  }

  /**
   * @returns {import('express').Handler}
   */
  function _setCookieHeader() {
    return function setCookieHeader(req, res, next) {
      async function mw() {
        let sessionClaims = libauth.get(req, "sessionClaims");
        let sessionToken = libauth.get(req, "sessionToken");
        let cookieOpts = Object.assign({}, cookieDefaults, {
          maxAge: parseDuration(sessionClaims.exp),
        });

        res.cookie(libOpts.cookieName, sessionToken, cookieOpts);

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    };
  }

  /**
   * @returns {import('express').Handler}
   */
  function _setTokens() {
    return function _setTokens(req, res, next) {
      async function mw() {
        let sessionClaims = libauth.get(req, "sessionClaims");
        if (sessionClaims) {
          let sessionToken = await _issueToken(sessionClaims);
          libauth.set(req, "sessionToken", sessionToken);
        }

        let idClaims = libauth.get(req, "idClaims");
        if (idClaims) {
          let idToken = await _issueToken(idClaims);
          libauth.set(req, "idToken", idToken);
        }

        let accessClaims = libauth.get(req, "accessClaims");
        if (accessClaims) {
          let accessToken = await _issueToken(accessClaims);
          libauth.set(req, "accessToken", accessToken);
        }

        let refreshClaims = libauth.get(req, "refreshClaims");
        if (refreshClaims) {
          let refreshToken = await _issueToken(refreshClaims);
          libauth.set(req, "refreshToken", refreshToken);
        }

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    };
  }

  /**
   * @returns {import('express').Handler}
   */
  function _sendTokens() {
    return function sendTokens(req, res, next) {
      let idToken = libauth.get(req, "idToken");
      let accessToken = libauth.get(req, "accessToken");
      let refreshToken = libauth.get(req, "refreshToken");

      res.json({
        id_token: idToken,
        access_token: accessToken,
        session_token: refreshToken,
      });
    };
  }

  /**
   * @param {String} [redirectUri]
   * @returns {import('express').Handler}
   */
  function _redirectWithTokens(redirectUri) {
    return function _redirecter(req, res, next) {
      async function mw() {
        if (!redirectUri) {
          redirectUri = libauth.get(req, "redirectUri");
        }
        if (!redirectUri) {
          throw E.DEVELOPER_ERROR("'redirectUri' was not set");
        }

        let query = {};
        let idToken = libauth.get(req, "idToken");
        if (idToken) {
          query.id_token = idToken;
        }
        let accessToken = libauth.get(req, "accessToken");
        if (accessToken) {
          query.access_token = accessToken;
        }
        let refreshToken = libauth.get(req, "refreshToken");
        if (refreshToken) {
          query.refresh_token = refreshToken;
        }

        let search = "";
        if (Object.keys(query).length) {
          //@ts-ignore
          search = new URLSearchParams(query).toString();
        }
        if (redirectUri.includes("?")) {
          search = `&${search}`;
        } else {
          search = `?${search}`;
        }

        res.redirect(302, `${redirectUri}${search}`);
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    };
  }

  /**
   * @returns {import('express').Handler}
   */
  function _getCookie() {
    return function getCookie(req, res, next) {
      async function mw() {
        let previousToken;
        if (req.signedCookies) {
          previousToken = req.signedCookies[libOpts.cookieName];
        }
        if (!previousToken) {
          next();
          return;
        }

        let sessionJws = await verifyJwt(previousToken).catch(function () {
          // ignore invalid token
        });

        libauth.set(req, {
          sessionJws: sessionJws,
        });

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    };
  }

  /** @type {import('express').Handler} */
  function _clearCookie(req, res, next) {
    let now = Date.now() - 10 * 60 * 1000;
    let expired = new Date(now);
    let cookieOpts = Object.assign({}, cookieDefaults, {
      expires: expired,
    });

    // TODO set name of refresh_token
    res.cookie(libOpts.cookieName, "", cookieOpts);

    next();
  }

  /**
   * @param {any} pluginOpts // TODO
   */
  function _oauth2(pluginOpts) {
    // TODO copy OIDC more or less
    throw new Error("not implemented");
  }

  /**
   * @returns {import('express').Handler}
   */
  function _wellKnownOidc() {
    return function (req, res) {
      res.json({
        iss: libOpts.issuer,
        jwks_uri: libOpts.issuer + "/.well-known/jwks.json",
      });
    };
  }

  /**
   * @returns {import('express').Handler}
   */
  function _wellKnownJwks() {
    return function (req, res) {
      res.json({ keys: [keypair.public] });
    };
  }

  /**
   * @param {MyAccessClaims | MyIdClaims} claims
   */
  async function _issueToken(claims) {
    // TODO I think this is necessary because the inner claims.exp is literal,
    // but the outer exp can be a duration. Need to double check.
    let exp = claims.exp;
    claims = Object.assign({}, claims);
    if (exp) {
      delete claims.exp;
    }
    return await Keypairs.signJwt({
      jwk: keypair.private,
      iss: libOpts.issuer,
      exp: exp,
      claims: claims,
    });
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

    // TODO initialize and require from ./lib/request.js
    //@ts-ignore
    let request = require("@root/request");

    let OIDC = require("./oidc.js");

    /**
     * @param {String} str
     */
    function startsWithProto(str) {
      // https:// http:// app: custom-x:
      let colonAt = str.indexOf(":");
      if (colonAt < 1) {
        return false;
      }
      if (colonAt < 10) {
        return true;
      }
      return false;
    }

    /**
     * @param {String} str
     */
    function stripTrailingSlash(str) {
      if (!str.endsWith("/")) {
        return str;
      }
      return str.slice(0, -1);
    }

    /** @type {import('express').Handler} */
    function setAuthUrl(req, res, next) {
      async function mw() {
        if (req.query.code || req.query.error) {
          next();
          return;
        }

        //let oidcAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth";
        let oidcConfig = await OIDC.getConfig(pluginOpts.iss);

        // ex: https://app.example.com/api/authn/session/oidc/accounts.google.com/redirect
        if (!pluginOpts.redirectUri) {
          pluginOpts.redirectUri = req.originalUrl || req.url;
        }
        if (!startsWithProto(pluginOpts.redirectUri)) {
          let redirectBase = "";
          if (!startsWithProto(libOpts.issuer)) {
            redirectBase += "https://";
          }
          redirectBase += stripTrailingSlash(libOpts.issuer);
          pluginOpts.redirectUri = `${redirectBase}/${pluginOpts.redirectUri}`;
        }

        let state = Crypto.randomInt(Math.pow(2, 32) - 1).toString(16);

        /* { clientId, scope } */
        let query = Object.assign(pluginOpts.authorizationQuery, req.query, {
          redirect_uri: pluginOpts.redirectUri,
          state: state,
          response_type: "code",
        });

        let url = OIDC.generateOidcUrl(
          oidcConfig.authorization_endpoint,
          query,
        );

        libauth.set(req, {
          strategy: "oidc_auth",
          authUrl: url.toString(),
        });
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    }

    /** @type {import('express').Handler} */
    function redirectToAuthUrl(req, res, next) {
      async function mw() {
        let authUrl = libauth.get(req, "authUrl");
        if (authUrl) {
          next();
          return;
        }

        // TODO XXXX hand control back?
        // "Found" (a.k.a. temporary redirect)
        res.redirect(302, authUrl);
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    }

    /** @type {import('express').Handler} */
    function exchangeCode(req, res, next) {
      async function mw() {
        let oidcConfig = await OIDC.getConfig(pluginOpts.iss);
        let clientId = pluginOpts.clientId;
        let clientSecret = pluginOpts.clientSecret;
        let code = req.query.code;

        if (!pluginOpts.redirectUri) {
          let ownPath = req.originalUrl || req.url;
          ownPath = new URL(`https://example.com${ownPath}`).pathname;
          let issuer = libOpts.issuer;
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

        libauth.set(req, {
          strategy: "oidc_code",
          oidcRequest: form,
          // TODO best name?
          oidcResponse: resp.body,
        });

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    }

    /** @type {import('express').Handler} */
    function verifyToken(req, res, next) {
      async function mw() {
        // For POST 'Implicit Grant' (Client-Side) Flow
        let jwt = (req.headers.authorization || "").replace(/^Bearer /, "");

        if (!jwt) {
          // For GET 'Authorization Code' (Server-Side Redirects) Flow
          let oidcResponse = libauth.get(req, "oidc");
          jwt = oidcResponse?.id_token || oidcResponse?.access_token;
        }

        let jws = await _oidcVerifyToken(jwt, oidcOpts);

        libauth.set(req, {
          strategy: "oidc",
          oidcJws: jws,
          oidcClaims: jws?.claims,
          //
          email: jws.claims.email,
          iss: jws.claims.iss,
          ppid: jws.claims.sub,
        });

        next();
      }

      //@ts-ignore
      return Promise.resolve().then(mw).catch(next);
    }

    return {
      // TODO make sure we're using the standard names
      setAuthUrl,
      redirectToAuthUrl,
      exchangeCode,
      verifyToken,
    };
  }

  let libauthKey = libOpts.authnParam;
  let libauth = {
    // init
    initialize: _initialize,
    _init: _init,
    set: _set,
    get: _get,

    // token-token
    refresh: _refresh,
    exchange: _exchange,

    // remove auth
    getCookie: _getCookie,
    clearCookie: _clearCookie,

    // replace auth
    credentials: _credentials,
    oidc: _oidc,
    oauth2: _oauth2,
    setClaims: _setClaims,
    setCookie: _setCookie,
    setTokens: _setTokens,
    setCookieHeader: _setCookieHeader,
    sendTokens: _sendTokens,
    redirectWithTokens: _redirectWithTokens,

    // helpers
    issueToken: _issueToken,

    // other helpers
    secureCompare: Util.secureCompare,

    // for verification
    wellKnownOidc: _wellKnownOidc,
    wellKnownJwks: _wellKnownJwks,
  };

  /** @param {any} _opts // TODO */
  //@ts-ignore
  libauth.challenge = require("./magic.js").create(libauth, libOpts);

  return libauth;
};
