"use strict";

let crypto = require("crypto");
let bodyParser = require("body-parser");
let app = require("@root/async-router").Router();
let cookieParser = require("cookie-parser");

// JWT Stuff
let Keyfetch = require("keyfetch");
let Keypairs = require("keypairs");

//
// Helper functions
//
let E = require("./errors.js");
let rnd = require("./rnd.js");
let parseDuration = require("./parse-duration.js");

async function parsePrivateKey(PRIVATE_KEY, keypair) {
  return Keypairs.parse({ key: PRIVATE_KEY })
    .catch(function (e) {
      // could not be parsed or was a public key
      if (PRIVATE_KEY) {
        console.warn(
          "Warn: 'PRIVATE_KEY' could not be parsed! Generating a temporary key."
        );
        console.warn(e);
      } else {
        console.warn(
          "Warn: 'PRIVATE_KEY' was not given. Generating an ephemeral (temporary) key."
        );
      }
      return Keypairs.generate();
    })
    .then(function (_keypair) {
      keypair.private = _keypair.private;
      keypair.public = _keypair.public;
    });
}

function verifyGoogleToken(clientId, verifyOpts) {
  if (!verifyOpts) {
    verifyOpts = {};
  }
  verifyOpts.iss = "https://accounts.google.com";
  return verifyOidcToken(verifyOpts, async function verifier(jws) {
    if (jws.claims.azp != clientId) {
      throw E.SUSPICIOUS_TOKEN();
    }
    if (!jws.claims.email_verified) {
      throw E.UNVERIFIED_OIDC_IDENTIFIER("email");
    }
  });
}

function verifyOidcToken(verifyOpts, verifier) {
  if (!verifier) {
    verifier = async function () {};
  }
  // Only tokens signed by accounts.google.com are valid

  return function (req, res, next) {
    let jwt = (req.headers.authorization || "").replace(/^Bearer /, "");
    Keyfetch.jwt
      .verify(jwt, verifyOpts)
      .then(async function (decoded) {
        if (decoded.claims.iss != verifyOpts.iss) {
          throw new Error(
            `unexpectedly passed issuer validation: '${decoded.claims.iss}' does not match '${verifyOpts.iss}'`
          );
        }
        await verifier(decoded);
        // "jws" is the technical term for a decoded "jwt"
        req._jws = decoded;
        next();
      })
      .catch(next);
  };
}

let defaultIdMaxAge = "24h";
let defaultAccessMaxAge = "1h";
let defaultRefreshMaxAge = "7d";

module.exports = function (issuer, PRIVATE_KEY, getClaims) {
  let opts = {
    oidc: {},
    notify: null,
    store: null,
    challengeMaxAge: 0,
    challengeMaxAttempts: 0,
    authnParam: "authn",
    DEVELOPMENT: "DEVELOPMENT" === process.env.ENV,
  };

  let iss = issuer;

  if (!getClaims) {
    throw new Error("you must provide a callback function for getClaims");
  }

  // Cookie Stuff
  // See https://github.com/BeyondCodeBootcamp/beyondcodebootcamp.com/blob/main/articles/express-cookies-cheatsheet.md
  let cookieDefaults = {
    signed: true,
    //path: "/api/authn/", // will be set by first middleware
    httpOnly: true,
    sameSite: "strict",
    secure: true,
    //expires: 0, // should be set on each issuance
  };

  if (PRIVATE_KEY) {
    if ("string" === typeof PRIVATE_KEY) {
      try {
        PRIVATE_KEY = require("fs").readFileSync(PRIVATE_KEY, "utf8").trim();
      } catch (e) {
        // ignore, probably wasn't a file anyway
      }
    } else {
      PRIVATE_KEY = JSON.stringify(PRIVATE_KEY.private || PRIVATE_KEY);
    }
    if (!opts.secret) {
      opts.secret = PRIVATE_KEY;
    }
  }

  // it is possible that this _might_ not happen until a millisecond
  // or two _after_ the server is accepting connections
  // See https://github.com/therootcompany/auth3000/issues/8
  let keypair = {};
  let keypairPromise = parsePrivateKey(PRIVATE_KEY, keypair);

  let googleVerifierOpts = {};

  // fill in ID claims defaults
  async function _getClaims(req) {
    let { claims, id_claims, access_claims, refresh_claims } = await getClaims(
      req
    );
    if (!claims) {
      claims = {};
    }
    if (!claims.iss && false !== claims.iss) {
      claims.iss = iss;
    }
    return { claims, id_claims, access_claims, refresh_claims };
  }

  async function grantTokens(allClaims) {
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
        iss: iss,
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
        iss: iss,
        exp: access_claims.exp || defaultAccessMaxAge,
        // optional claims
        claims: access_claims,
      });
    }

    return { id_token, access_token };
  }

  async function refreshSession(res, allClaims) {
    let refresh_token;
    let maxAge;

    let refresh_claims = Object.assign(
      {},
      allClaims.claims || {},
      allClaims.refresh_claims || allClaims.id_claims || {}
    );
    maxAge = refresh_claims.exp || defaultRefreshMaxAge;
    refresh_token = await Keypairs.signJwt({
      jwk: keypair.private,
      iss: iss,
      exp: maxAge,
      claims: refresh_claims,
    });

    let cookieOpts = Object.assign({}, cookieDefaults, {
      maxAge: parseDuration(maxAge),
    });
    res.cookie("refresh_token", refresh_token, cookieOpts);
  }

  async function grantTokensAndCookie(allClaims, req, res) {
    let { id_token, access_token } = await grantTokens(allClaims);
    if (req.body) {
      allClaims.trust_device = req.body.trust_device;
    }
    await refreshSession(res, allClaims);
    return { id_token, access_token };
  }

  async function verifySession(req) {
    if (!req.signedCookies.refresh_token) {
      throw E.INVALID_SESSION();
    }

    return Keyfetch.jwt.verify(req.signedCookies.refresh_token, {
      iss: iss,
    });
  }

  async function verifyIdToken(req) {
    let jwt = (req.headers.authorization || "").replace("Bearer ", "");
    let pub;

    if (keypair) {
      pub = keypair.public;
    }

    let jws = await Keyfetch.jwt.verify(jwt, {
      issuers: [iss], // or ['*']
      jwk: pub,
    });

    return jws;
  }

  async function verifyJwt(jwt) {
    let pub;
    if (keypair) {
      pub = keypair.public;
    }
    let jws = await Keyfetch.jwt.verify(jwt, {
      issuers: [iss], // or ['*']
      jwk: pub,
    });
    return jws;
  }

  async function router() {
    if (!opts.secret) {
      console.warn(
        "Warn: 'secret', which is used for cookies and authentication challenges was not given. Generating an ephemeral (temporary) secret."
      );
      opts.secret = rnd(16, "hex");
    }

    // Dev / Localhost Stuff
    if (opts.DEVELOPMENT && !opts.__DEVELOPMENT) {
      opts.__DEVELOPMENT = true;
      console.info("[ENV=DEVELOPMENT] Allow Insecure (localhost) Cookies");
      // allow non-https cookies
      cookieDefaults.secure = false;
    }

    //
    // API Middleware & Handlers
    //
    let byIdToken = async function (req, res) {
      let jws = await verifyIdToken(req);

      req[opts.authnParam] = {
        strategy: "jwt",
        jws: jws,
      };
      let allClaims = await _getClaims(req);
      req[opts.authnParam] = null;

      let access_claims = Object.assign(
        {},
        allClaims.claims || {},
        allClaims.access_claims || {}
      );
      let jwt = await Keypairs.signJwt({
        jwk: keypair.private,
        iss: iss,
        exp: "24h",
        // optional claims
        claims: access_claims,
      });

      res.json({ access_token: jwt });
    };
    let byCookie = async function (req, res) {
      let jws = await verifySession(req);

      req[opts.authnParam] = {
        strategy: "refresh",
        jws: jws,
      };
      let allClaims = await _getClaims(req);
      req[opts.authnParam] = null;

      let tokens = await grantTokens(allClaims);
      res.json(tokens);
    };
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

      req[opts.authnParam] = { jti: jws.claims.jti, jws };
      await opts.logout(req);
    };

    //
    // API Routes
    //
    app.use("/", function (req, res, next) {
      if (!cookieDefaults.path) {
        // ex: cookieDefaults.path = "/api/authn";
        cookieDefaults.path = req.baseUrl;
      }
      next();
    });
    app.use("/", cookieParser(opts.secret)); // needed to set cookies?

    app.post("/exchange", byIdToken);
    app.post("/refresh", byCookie); // cookies only parsed here
    app.delete("/session", logout);

    return app;
  }

  function _init() {
    if (!opts.__PARSER) {
      opts.__PARSER = true;
      app.use("/", bodyParser.json({ limit: "100kb" }));
    }
  }

  return {
    challenge: function (_opts) {
      opts = Object.assign(opts, _opts);
      _init();

      if (!opts.store) {
        console.warn(
          "Warn: no 'store' given, falling back to in-memory (single-system only) store"
        );
        opts.store = require("./memory-store.js");
      }

      if (!opts.notify) {
        console.warn("Warn: no 'notify' given, cannot send challenges");
      }

      let byChallenge = require("./magic-link.js")({
        DEVELOPMENT: opts.DEVELOPMENT,
        HMAC_SECRET: opts.secret,
        notify: opts.notify,
        store: opts.store,
        iss,
        _authnParam: opts.authnParam,
        _getClaims,
        _grantTokensAndCookie: grantTokensAndCookie,
      });
      app.use("/challenge", byChallenge);
    },
    credentials: function (_opts) {
      opts = Object.assign(opts, _opts);
      _init();

      let byCredentials = async function (req, res) {
        req[opts.authnParam] = {
          strategy: "credentials",
        };
        let allClaims = await _getClaims(req);
        req[opts.authnParam] = null;

        let tokens = await grantTokensAndCookie(allClaims, req, res);
        res.json(tokens);
      };

      app.post("/session", byCredentials);
    },
    logout: function (fn) {
      opts.logout = fn;
    },
    oidc: function (_opts) {
      opts.oidc = Object.assign(opts.oidc, _opts);
      _init();

      if (opts.DEVELOPMENT && !opts.__DEVELOPMENT_2) {
        opts.__DEVELOPMENT_2 = true;
        if (opts.oidc?.google?.clientId) {
          console.info("[ENV=DEVELOPMENT] Allow Expired Google Tokens");
          // allow tests with expired google example token
          googleVerifierOpts.exp = false;
        }
      }
      if (opts.oidc?.google?.clientId) {
        let byOidc = async function (req, res) {
          req[opts.authnParam] = {
            strategy: "oidc",
            email: req._jws.claims.email,
            iss: req._jws.claims.iss,
            ppid: req._jws.claims.sub,
            oidc_claims: req._jws.claims,
          };
          let allClaims = await _getClaims(req);
          req[opts.authnParam] = null;

          let tokens = await grantTokensAndCookie(allClaims, req, res);
          res.json(tokens);
        };
        app.post(
          "/session/oidc/google.com",
          verifyGoogleToken(opts.oidc.google.clientId, googleVerifierOpts),
          byOidc
        );
      }
    },
    options: function (_opts) {
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
            iss: iss,
            jwks_uri: iss + "/.well-known/jwks.json",
          });
        }
      );
      wellKnown.get("/.well-known/jwks.json", async function (req, res) {
        res.json({ keys: [keypair.public] });
      });

      return wellKnown;
    },
  };
};
