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

function parsePrivateKey(PRIVATE_KEY) {
  let keypair = {};

  try {
    PRIVATE_KEY = require("fs").readFileSync(PRIVATE_KEY, "utf8").trim();
  } catch (e) {
    // ignore, probably wasn't a file anyway
  }
  Keypairs.parse({ key: PRIVATE_KEY })
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

  return keypair;
}

async function verifySession(req) {
  if (!req.signedCookies.refresh_token) {
    throw E.INVALID_SESSION();
  }

  return Keyfetch.jwt.verify(req.signedCookies.refresh_token);
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
      throw E.UNVERIFIED_EMAIL();
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
        req.jws = decoded;
        next();
      })
      .catch(next);
  };
}

module.exports = function (
  issuer,
  HMAC_SECRET,
  PRIVATE_KEY,
  {
    // required
    getClaims,
    // feature-based
    oidc = { google: {} },
    notify,
    store,
    // optional
    routePrefix,
    challengeMaxAge,
    challengeMaxAttempts,
    authnParam,
  }
) {
  let DEVELOPMENT = "DEVELOPMENT" === process.env.ENV;
  let defaultIdMaxAge = "24h";
  let defaultAccessMaxAge = "1h";
  let defaultRefreshMaxAge = "7d";
  let iss = issuer;

  if (!authnParam) {
    authnParam = "authn";
  }
  if (!store) {
    store = require("./memory-store.js");
  }

  if (!getClaims) {
    throw new Error("you must provide a callback function for getClaims");
  }

  if (HMAC_SECRET && HMAC_SECRET.length < 16) {
    HMAC_SECRET = "";
    console.warn();
    console.warn(
      "Warn: 'HMAC_SECRET=%s' must provide at least 96-bits of entropy.",
      HMAC_SECRET
    );
    console.warn("Warn: Try one of these:");
    console.warn("Warn:");
    console.warn("Warn:\t openssl rand -base64 16");
    console.warn("Warn:\t xxd -l16 -ps /dev/urandom");
    console.warn("Warn:\t crypto.randomBytes(16).toString('base64');");
    console.warn("Warn:");
    console.warn(
      "Warn: See https://therootcompany.com/blog/how-to-generate-secure-random-strings/ "
    );
    console.warn("Warn:");
    console.warn();
  }

  if (!HMAC_SECRET) {
    HMAC_SECRET = crypto.randomBytes(16).toString("hex");
    console.warn(
      "Warn: 'HMAC_SECRET', which is used for cookies and authentication challenges was not given. Generating an ephemeral (temporary) secret."
    );
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

  if (!PRIVATE_KEY) {
    PRIVATE_KEY = "";
  }
  if ("string" !== typeof PRIVATE_KEY) {
    PRIVATE_KEY = JSON.stringify(PRIVATE_KEY.private || PRIVATE_KEY);
  }
  // it is possible that this _might_ not happen until a millisecond
  // or two _after_ the server is accepting connections
  // See https://github.com/therootcompany/auth3000/issues/8
  let keypair = parsePrivateKey(PRIVATE_KEY);

  // Dev / Localhost Stuff
  let googleVerifierOpts = {};
  if (DEVELOPMENT) {
    console.info("[ENV=DEVELOPMENT] Allow Insecure (localhost) Cookies");
    // allow non-https cookies
    cookieDefaults.secure = false;

    if (oidc.google.clientId) {
      console.info("[ENV=DEVELOPMENT] Allow Expired Google Tokens");
      // allow tests with expired google example token
      googleVerifierOpts.exp = false;
    }
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
      allClaims.refresh_claims || {}
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

  //
  // API Middleware & Handlers
  //
  let byOidc = async function (req, res) {
    req[authnParam] = {
      strategy: "oidc",
      email: req.jws.claims.email,
      iss: req.jws.claims.iss,
      ppid: req.jws.claims.sub,
    };
    let allClaims = await _getClaims(req);
    req[authnParam] = null;

    let tokens = await grantTokensAndCookie(allClaims, req, res);
    res.json(tokens);
  };
  let byCredentials = async function (req, res) {
    req[authnParam] = {
      strategy: "credentials",
    };
    let allClaims = await _getClaims(req);
    req[authnParam] = null;

    let tokens = await grantTokensAndCookie(allClaims, req, res);
    res.json(tokens);
  };
  let byChallenge = require("./magic-link.js")({
    DEVELOPMENT,
    HMAC_SECRET,
    notify,
    store,
    iss,
    _authnParam: authnParam,
    _getClaims,
    _grantTokensAndCookie: grantTokensAndCookie,
  });
  let byIdToken = async function (req, res) {
    let jws = await verifyIdToken(req);

    req[authnParam] = {
      strategy: "jwt",
      jws: jws,
    };
    let allClaims = await _getClaims(req);
    req[authnParam] = null;

    let jwt = await Keypairs.signJwt({
      jwk: keypair.private,
      iss: iss,
      exp: "24h",
      // optional claims
      claims: allClaims,
    });

    res.json({ access_token: jwt });
  };
  let byCookie = async function (req, res) {
    let jws = await verifySession(req);

    req[authnParam] = {
      strategy: "refresh",
      jws: jws,
    };
    let allClaims = await _getClaims(req);
    req[authnParam] = null;

    let tokens = await grantTokens(allClaims);
    res.json(tokens);
  };
  let logout = async function (req, res) {
    let now = Date.now() - 10 * 60 * 1000;
    let expired = new Date(now);
    let cookieOpts = Object.assign({}, cookieDefaults, { expires: expired });
    res.cookie("refresh_token", "", cookieOpts);

    res.json({ success: true });
  };

  //
  // API Routes
  //
  app.use("/", bodyParser.json({ limit: "100kb" }));
  app.use("/", function (req, res, next) {
    if (!cookieDefaults.path) {
      // ex: cookieDefaults.path = "/api/authn";
      cookieDefaults.path = req.baseUrl;
    }
    next();
  });
  app.use("/", cookieParser(HMAC_SECRET)); // needed to set cookies?

  if (oidc.google.clientId) {
    app.post(
      "/session/oidc/google.com",
      verifyGoogleToken(oidc.google.clientId, googleVerifierOpts),
      byOidc
    );
  }
  app.post("/session", byCredentials);
  app.use("/challenge", byChallenge);
  app.post("/exchange", byIdToken);
  app.post("/refresh", byCookie); // cookies only parsed here
  app.delete("/session", logout);

  //
  // OIDC Well-Known Handlers
  //
  app.wellKnown = require("@root/async-router").Router();
  app.wellKnown.get(
    "/.well-known/openid-configuration",
    async function (req, res) {
      res.json({
        iss: iss,
        jwks_uri: iss + "/.well-known/jwks.json",
      });
    }
  );
  app.wellKnown.get("/.well-known/jwks.json", async function (req, res) {
    res.json({ keys: [keypair.public] });
  });

  return app;
};
