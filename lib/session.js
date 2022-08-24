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
 * @param {JwsPriv} privkey
 * @returns {JwsPub}
 */
LibAuth.jwkToPublic = function (privkey) {
  let pub = {
    kty: privkey.kty,
    // EC: crv, x, y
    crv: privkey.crv,
    x: privkey.x,
    y: privkey.y,
    // RSA: alg, e, n
    alg: privkey.alg,
    e: privkey.e,
    n: privkey.n,
    // metadata
    kid: privkey.kid,
    use: "sig",
  };

  // if we ever need an object key, make a copy first
  //return JSON.parse(JSON.stringify(pub));
  return pub;
};

/**
 * @param {JwsPriv} PRIVATE_KEY
 * @param {Keypair} keypair
 * @returns JwsPub
 */
function parsePrivateKey(PRIVATE_KEY, keypair) {
  keypair.private = PRIVATE_KEY;

  if (!keypair.public) {
    keypair.public = LibAuth.jwkToPublic(keypair.private);
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
 * @typedef MyLibAuthOpts
 * @property {String} [accessMaxAge]
 * @property {String} [cookieName]
 * @property {String} [cookiePath]
 * @property {String} [idMaxAge]
 * @property {String} [propName]
 * @property {String} [refreshMaxAge]
 * @property {String} [sessionMaxAge]
 * @property {String} [trustedMaxAge]
 */

/**
 * @param {string} issuer
 * @param {JwsPriv} PRIVATE_KEY
 * @param {MyLibAuthOpts} myOptions
 */
LibAuth.create = function (issuer, PRIVATE_KEY, myOptions) {
  // TODO set as part of creation
  // { idClaims: { exp: '24h' }

  /** @type LibAuthOpts */
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
      issuers: [libOpts.issuer],
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
      debug: false,

      /** @param {String} k */
      get: function (k) {
        if (!k || "*" === k) {
          return cache;
        }
        return cache[k];
      },
      /**
       * @param {String|Object} key
       * @param {any} value
       * */
      set: function (key, value) {
        if ("object" !== typeof key) {
          //@ts-ignore
          if (req[libauthKey].debug) {
            console.debug(`[libauth] set 'req.${libauthKey}.${key}':`);
            console.debug(JSON.stringify(value, null, 2));
          }

          //@ts-ignore
          cache[key] = value;
          return;
        }

        //@ts-ignore
        if (req[libauthKey].debug) {
          console.debug(`[libauth] patch 'req.${libauthKey}':`);
          console.debug(JSON.stringify(key, null, 2));
        }

        // libauth.set(req, { foo: 'bar', baz: 'quux' })
        Object.keys(key).forEach(function (k) {
          ///@ts-ignore
          cache[k] = key[k];
        });
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

    ///@ts-ignore
    req[libauthKey].set(key, value);
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
  function _readCredentials(_credOpts) {
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
    function readCredentials(req, res, next) {
      let creds;

      let authBasic = req.headers["authorization"] || "";
      let authPre = "Basic ";
      if (false !== credOpts.basic && authBasic.startsWith(authPre)) {
        creds = Util.decodeAuthorizationBasicValue(
          authBasic.slice(authPre.length),
        );
      }

      if (!creds?.username) {
        let userKey = credOpts.username || "username";
        let passKey = credOpts.password || "password";
        creds = {
          username: req.body[userKey],
          password: req.body[passKey],
        };
      }

      let credentials = {
        strategy: "credentials",
        username: creds.username,
        password: creds.password,
        valid: null,
      };
      libauth.set(req, credentials);
      libauth.set(req, "credentials", credentials);
      libauth.set(req, "authMethods", ["credentials"]);

      next();
    }

    return promisifyHandler(readCredentials);
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
  function _initClaims() {
    /** @type {import('express').Handler} */
    async function initClaims(req, res, next) {
      if (libauth.get(req, "error")) {
        next();
        return;
      }

      let templateClaims;
      let authTime;
      let jti;
      let sub;

      if (!libauth.get(req, "newSession")) {
        templateClaims = libauth.get(req, "userClaims");
      } else {
        templateClaims =
          libauth.get(req, "idClaims") || libauth.get(req, "accessClaims");
      }
      authTime = templateClaims.auth_time;
      jti = templateClaims.jti;
      sub = templateClaims.sub;

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

      let amr = libauth.get(req, "authMethods") || [];
      if (!amr.length) {
        amr = undefined;
      }
      let baseClaims = {
        jti: jti,
        iss: libOpts.issuer,
        sub: sub,
        auth_time: authTime,
        amr: amr,
      };

      _setIdClaims(req, baseClaims);
      _setAccessClaims(req, baseClaims);
      _setRefreshClaims(req, baseClaims);
      _setSessionClaims(req, baseClaims);

      next();
    }

    return promisifyHandler(initClaims);
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
  function _initCookie() {
    /** @type {import('express').Handler} */
    async function initCookie(req, res, next) {
      if (libauth.get(req, "error")) {
        next();
        return;
      }

      // Make previous session available, if any
      let previousJws = await verifySessionJwt(req).catch(function (err) {
        // for debugging
        libauth.set(req, "sessionError", err);
      });
      if (previousJws) {
        libauth.set(req, {
          currentSessionJws: previousJws,
          currentSessionClaims: previousJws?.claims,
        });
      }

      // Generate new session
      let sessionClaims = libauth.get(req, "sessionClaims");
      let sessionToken = await libauth.issueToken(sessionClaims);

      libauth.set(req, "sessionToken", sessionToken);

      next();
    }

    return promisifyHandler(initCookie);
  }

  /**
   * @returns {import('express').Handler}
   */
  function _initTokens() {
    /** @type {import('express').Handler} */
    async function initTokens(req, res, next) {
      if (libauth.get(req, "error")) {
        next();
        return;
      }

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

    return promisifyHandler(initTokens);
  }

  /**
   * @returns {import('express').Handler}
   */
  function _setCookieHeader() {
    /** @type {import('express').Handler} */
    async function setCookieHeader(req, res, next) {
      if (libauth.get(req, "error")) {
        throw libauth.get(req, "error");
      }

      let sessionClaims = libauth.get(req, "sessionClaims");
      let sessionToken = libauth.get(req, "sessionToken");
      let cookieOpts = Object.assign({}, cookieDefaults, {
        maxAge: parseDuration(sessionClaims.exp),
      });

      res.cookie(libOpts.cookieName, sessionToken, cookieOpts);

      next();
    }

    return promisifyHandler(setCookieHeader);
  }

  /**
   * @returns {import('express').Handler}
   */
  function _sendTokens() {
    return function sendTokens(req, res, next) {
      if (libauth.get(req, "error")) {
        throw libauth.get(req, "error");
      }

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
   * @returns {import('express').Handler}
   */
  function _sendOk() {
    return function sendTokens(req, res, next) {
      if (libauth.get(req, "error")) {
        throw libauth.get(req, "error");
      }

      res.json({ success: true });
    };
  }

  /**
   * @returns {import('express').ErrorRequestHandler}
   */
  function _sendError() {
    return function sendError(err, req, res, next) {
      let errResp = {
        success: false,
        code: err.code,
        status: err.status || 500,
        message: err.message,
      };

      res.statusCode = errResp.status;
      if (500 == res.statusCode) {
        console.error(err.stack);
      }
      res.json(errResp);
    };
  }

  /**
   * @returns {import('express').ErrorRequestHandler}
   */
  function _captureError() {
    return function captureError(err, req, res, next) {
      libauth.set(req, "error", err);
      next();
    };
  }

  /**
   * @returns {import('express').Handler}
   */
  function _releaseError() {
    return function captureError(req, res, next) {
      if (libauth.get(req, "error")) {
        throw libauth.get(req, "error");
      }
    };
  }

  /**
   * @param {String} [redirectUri]
   * @returns {import('express').Handler}
   */
  function _redirectWithQuery(redirectUri) {
    /** @type {import('express').Handler} */
    async function _redirecter(req, res, next) {
      /*
      if (libauth.get(req, "error")) {
        throw libauth.get(req, "error");
      }
      */

      if (!redirectUri) {
        redirectUri = libauth.get(req, "redirectUri");
      }
      if (!redirectUri) {
        throw E.DEVELOPER_ERROR("'redirectUri' was not set");
      }

      let query = {};

      let errResp = libauth.get(req, "error") || libauth.get(req, "oidcError");
      if (errResp?.error) {
        query.error = errResp.code || errResp.error;
      }
      if (errResp?.error_description) {
        query.error_description = errResp.error_description || errResp.message;
      }
      if (errResp?.error_uri || errResp?.error_url) {
        query.error_uri =
          errResp.error_url || errResp.error_uri || errResp.uri || errResp.url;
      }

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

    return promisifyHandler(_redirecter);
  }

  /**
   * @param {any} opts
   * @returns {import('express').Handler}
   */
  function _readCookie(opts) {
    /** @type {import('express').Handler} */
    async function readCookie(req, res, next) {
      let prevToken;
      if (req.signedCookies) {
        prevToken = req.signedCookies[libOpts.cookieName];
      }
      if (!prevToken) {
        if (opts?.__required) {
          throw E.SESSION_INVALID();
          //throw E.MISSING_TOKEN();
        }
        next();
        return;
      }

      let currentJws = await verifyJwt(prevToken).catch(function (err) {
        if (opts?.__required) {
          throw err;
        }
        // for debugging (otherwise ignore invalid token)
        libauth.set(req, "sessionError", err);
      });
      if (!currentJws) {
        next();
        return;
      }

      libauth._assertMaxAge(req, currentJws.claims.auth_time);

      libauth.set(req, {
        currentSessionJws: currentJws,
        currentSessionClaims: currentJws.claims,
      });
      if (!libauth.get(req, "userClaims")) {
        libauth.set(req, "userClaims", currentJws.claims);
      }

      next();
    }

    return promisifyHandler(readCookie);
  }

  function _requireCookie() {
    return _readCookie({ __required: true });
  }

  /**
   * @param {any} opts
   * @returns {import('express').Handler}
   */
  function _readBearer(opts) {
    /** @type {import('express').Handler} */
    async function readBearer(req, res, next) {
      if (!(req.headers.authorization || "").startsWith("Bearer ")) {
        if (opts?.__required) {
          //throw E.SESSION_INVALID();
          throw E.MISSING_TOKEN();
        }
        next();
        return;
      }

      let bearerJws = await verifyBearerJwt(req);
      libauth.set(req, "bearerJws", bearerJws);
      libauth.set(req, "bearerClaims", bearerJws.claims);
      if (!libauth.get(req, "userClaims")) {
        libauth.set(req, "userClaims", bearerJws.claims);
      }

      libauth._assertMaxAge(req, bearerJws.claims.auth_time);

      next();
    }

    return promisifyHandler(readBearer);
  }

  /**
   * @param {import('express').Request} req
   * @param {Number} epoch
   */
  function _assertMaxAge(req, epoch) {
    let maxAgeStr = req.body.max_age || req.query.max_age;
    if (!maxAgeStr) {
      return;
    }

    let maxAge = parseInt(maxAgeStr, 10) * 1000;
    let authTime = epoch * 1000;
    let now = Date.now();
    let fresh = now - authTime < maxAge;
    if (!fresh) {
      // TODO
      throw new Error(
        `'auth_time:${authTime}' is not within 'max_age:${maxAge}'`,
      );
    }
  }

  function _requireBearer() {
    return _readBearer({ __required: true });
  }

  function _expireCookie() {
    /** @type {import('express').Handler} */
    return function _expireCookie(req, res, next) {
      let now = Date.now() - 10 * 60 * 1000;
      let expired = new Date(now);
      let cookieOpts = Object.assign({}, cookieDefaults, {
        expires: expired,
      });

      // TODO set name of refresh_token
      res.cookie(libOpts.cookieName, "", cookieOpts);

      next();
    };
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
    return LibAuth.wellKnownOidc({ issuer: libOpts.issuer });
  }

  /**
   * @returns {import('express').Handler}
   */
  function _wellKnownJwks() {
    return LibAuth.wellKnownJwks({
      issuer: libOpts.issuer,
      jwks: [keypair.public],
    });
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
  function _xoidc(pluginOpts) {
    let oidcOpts = Object.assign({}, pluginOpts);

    // TODO initialize and require from ./lib/request.js
    //@ts-ignore
    let request = require("@root/request");

    let OIDC = require("./oidc.js");

    /**
     * Verifies a 3rd-Party Token
     * @param {any} jwt
     * @param {OidcVerifyOpts} verifyOpts
     */
    async function _oidcVerifyToken(jwt, verifyOpts) {
      let keyfetchOpts = {
        issuers: [verifyOpts.iss],
        exp: verifyOpts.exp ?? true,
      };

      // JWS is the technical term for a decoded JWT
      let jws = await Keyfetch.jwt.verify(jwt, keyfetchOpts);

      if ("function" === typeof verifyOpts.pluginVerify) {
        verifyOpts.pluginVerify(jws);
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
    async function generateAuthUrl(req, res, next) {
      if (req.query.code || req.query.error) {
        next();
        return;
      }

      //let oidcAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth";
      let oidcConfig = await OIDC.getConfig(pluginOpts.issuer);

      // ex: https://app.example.com/api/authn/session/oidc/accounts.google.com/redirect
      if (!pluginOpts.redirectUri) {
        pluginOpts.redirectUri = req.originalUrl || req.url;
      }
      // TODO SECURITY check redirectUri
      if (!startsWithProto(pluginOpts.redirectUri)) {
        let redirectBase = "";
        if (!startsWithProto(libOpts.issuer)) {
          redirectBase += "https://";
        }
        redirectBase += stripTrailingSlash(libOpts.issuer);
        pluginOpts.redirectUri = `${redirectBase}${pluginOpts.redirectUri}`;
      }

      let state = Crypto.randomInt(Math.pow(2, 32) - 1).toString(16);

      /* { clientId, scope } */
      let query = Object.assign(pluginOpts.authQuery, req.query, {
        redirect_uri: pluginOpts.redirectUri,
        state: state,
        response_type: "code",
      });

      let url = OIDC.generateOidcUrl(oidcConfig.authorization_endpoint, query);

      libauth.set(req, {
        strategy: "oidc_auth",
        authUrl: url.toString(),
      });

      next();
    }

    /** @type {import('express').Handler} */
    async function redirectToAuthUrl(req, res, next) {
      let authUrl = libauth.get(req, "authUrl");
      if (!authUrl) {
        next();
        return;
      }

      // TODO XXXX hand control back?
      // "Found" (a.k.a. temporary redirect)
      res.redirect(302, authUrl);
    }

    /** @type {import('express').Handler} */
    async function getCodeParams(req, res, next) {
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

      libauth.set(req, {
        strategy: "oidc_code",
        oidcRequest: form,
      });

      next();
    }

    /** @type {import('express').Handler} */
    async function requestToken(req, res, next) {
      let oidcTokenRequest = libauth.get(req, "oidcRequest");
      let oidcConfig = await OIDC.getConfig(pluginOpts.issuer);
      // TODO get the code and exchange it
      let resp = await request({
        method: "POST",
        url: oidcConfig.token_endpoint,
        // www-urlencoded...
        json: true,
        form: oidcTokenRequest,
      });

      libauth.set(req, {
        strategy: "oidc_code",
        oidcResponse: resp.body,
      });

      next();
    }

    /** @type {import('express').Handler} */
    async function verifyToken(req, res, next) {
      // For POST 'Implicit Grant' (Client-Side) Flow
      let jwt = (req.headers.authorization || "").replace(/^Bearer /, "");

      if (!jwt) {
        // For GET 'Authorization Code' (Server-Side Redirects) Flow
        let oidcResponse = libauth.get(req, "oidcResponse");
        jwt = oidcResponse?.id_token || oidcResponse?.access_token;

        if (!jwt) {
          libauth.set(
            req,
            "oidcError",
            oidcResponse || {
              error: "libauth:invalid_oidc_response",
              error_description: "did not receive response from oidc provider",
            },
          );
          next(E.OIDC_ERROR());
          return;
        }
      }

      let jws = await _oidcVerifyToken(jwt, oidcOpts.claims);

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

    return {
      // TODO make sure we're using the standard names
      generateAuthUrl: promisifyHandler(generateAuthUrl),
      redirectToAuthUrl: promisifyHandler(redirectToAuthUrl),
      getCodeParams: promisifyHandler(getCodeParams),
      requestToken: promisifyHandler(requestToken),
      verifyToken: promisifyHandler(verifyToken),
    };
  }

  /**
   * @param {import('express').Handler} handler
   * @returns {import('express').Handler}
   */
  function promisifyHandler(handler) {
    return function _promisifyHandler(req, res, next) {
      return Promise.resolve()
        .then(async function () {
          return await handler(req, res, next);
        })
        .catch(next);
    };
  }

  /**
   * @param {import('express').ErrorRequestHandler} errHandler
   * @returns {import('express').ErrorRequestHandler}
   */
  function promisifyErrHandler(errHandler) {
    return function _promisifyErrHandler(err, req, res, next) {
      return Promise.resolve()
        .then(async function () {
          //@ts-ignore
          return await errHandler(err, req, res, next);
        })
        .catch(next);
    };
  }

  let libauthKey = libOpts.authnParam;
  let libauth = {
    // init
    initialize: _initialize,
    _init: _init,
    set: _set,
    get: _get,

    // remove auth
    readCookie: _readCookie,
    requireCookie: _requireCookie,
    expireCookie: _expireCookie,

    // read auth
    readBearerClaims: _readBearer,
    readToken: _readBearer,
    requireBearerClaims: _requireBearer,
    requireToken: _requireBearer,

    // replace auth
    readCredentials: _readCredentials,
    oauth2: _oauth2,
    //
    newSession: _newSession,
    initClaims: _initClaims,
    initCookie: _initCookie,
    initTokens: _initTokens,
    setCookieHeader: _setCookieHeader,
    sendTokens: _sendTokens,
    redirectWithQuery: _redirectWithQuery,
    captureError: _captureError,
    releaseError: _releaseError,
    sendOk: _sendOk,
    sendError: _sendError,

    // helpers
    issueToken: _issueToken,
    promisifyHandler: promisifyHandler,
    promisifyErrHandler: promisifyErrHandler,

    // other helpers
    secureCompare: Util.secureCompare,
    _assertMaxAge: _assertMaxAge,

    // for verification
    wellKnownOidc: _wellKnownOidc,
    wellKnownJwks: _wellKnownJwks,
  };

  /** @param {any} _opts // TODO */
  //@ts-ignore
  libauth.challenge = require("./magic.js").create(libauth, libOpts);
  //@ts-ignore
  libauth.oidc = require("./oidc.js").create(libauth, libOpts);

  return libauth;
};

/**
 * @param {Object} opts
 * @param {String} opts.issuer
 * @returns {import('express').Handler}
 */
LibAuth.wellKnownOidc = function ({ issuer }) {
  return function (req, res) {
    res.json({
      iss: issuer,
      jwks_uri: issuer + "/.well-known/jwks.json",
    });
  };
};

/**
 * @param {Object} opts
 * @param {String} opts.issuer
 * @param {Array<JwsPub>} opts.jwks
 * @returns {import('express').Handler}
 */
LibAuth.wellKnownJwks = function ({ issuer, jwks }) {
  return function (req, res) {
    res.json({ keys: jwks });
  };
};
