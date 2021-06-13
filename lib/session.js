"use strict";

// TODO eliminate process.env global vars

let bodyParser = require("body-parser");
let app = require("@root/async-router").Router();

// Cookie Stuff
// See https://github.com/BeyondCodeBootcamp/beyondcodebootcamp.com/blob/main/articles/express-cookies-cheatsheet.md
let cookieParser = require("cookie-parser");
// TODO ^^
let COOKIE_SECRET = process.env.COOKIE_SECRET;
if (!COOKIE_SECRET) {
  COOKIE_SECRET = require("crypto").randomBytes(16).toString("hex");
  console.warn(
    "Warn: 'COOKIE_SECRET' was not given. Generating an ephemeral (temporary) secret."
  );
}
let cookieDefaults = {
  signed: true,
  path: "/api/authn/",
  httpOnly: true,
  sameSite: "strict",
  secure: true,
  //expires: 0, // should be set on each issuance
};

// JWT Stuff
let Keyfetch = require("keyfetch");
let Keypairs = require("keypairs");

//
// Helper functions
//
async function verifySession(req) {
  if (!req.signedCookies.id_token) {
    let err = Error("Missing or invalid session. Logout and login again.");
    err.status = 400;
    err.code = "INVALID_SESSION";
    throw err;
  }

  // TODO rethink this
  // skip verification of token because the cookie is already signed and verified
  return Keyfetch.jwt.decode(req.signedCookies.id_token);
}

function verifyGoogleToken(clientId, verifyOpts) {
  if (!verifyOpts) {
    verifyOpts = {};
  }
  verifyOpts.iss = "https://accounts.google.com";
  return verifyOidcToken(verifyOpts, async function verifier(jws) {
    if (jws.claims.azp != clientId) {
      let err = new Error("the given google token does not belong to this app");
      err.code = "INVALID_TOKEN";
      throw err;
    }
    if (!jws.claims.email_verified) {
      let err = new Error("Google account has not yet been verified.");
      err.code = "INVALID_TOKEN";
      throw err;
    }
  });
}

function verifyOidcToken(verifyOpts, verifier) {
  if (!verifier) {
    verifier = async function () {};
  }
  // Only tokens signed by accounts.google.com are valid

  return function (req, res, next) {
    let jwt = (req.headers.authorization || "").replace("Bearer ", "");
    if (!jwt) {
      console.debug("DEBUG req.headers:");
      console.debug(req.headers);
    }
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

module.exports = function ({ keypair, iss, getIdClaims, getAccessClaims }) {
  if (!getIdClaims) {
    if (!getAccessClaims) {
      throw new Error(
        "you must provide a callback function for at least one of getIdClaims and getAccessClaims"
      );
    }
    getIdClaims = getAccessClaims;
  } else if (!getAccessClaims) {
    getAccessClaims = getIdClaims;
  }

  if (!keypair || "string" === typeof keypair) {
    Keypairs.parse({ key: keypair })
      .catch(function (e) {
        // could not be parsed or was a public key
        if (keypair) {
          console.warn(
            "Warn: 'keypair' could not be parsed! Generating a temporary key."
          );
          console.warn(e);
        } else {
          console.warn(
            "Warn: 'keypair' was not given. Generating an ephemeral (temporary) key."
          );
        }
        return Keypairs.generate();
      })
      .then(function (_keypair) {
        keypair = _keypair;
      });
  }

  // Dev / Localhost Stuff
  let googleVerifierOpts = {};
  if ("DEVELOPMENT" === process.env.ENV) {
    // allow tests with expired google example token
    googleVerifierOpts.exp = false;
    // allow non-https cookies
    cookieDefaults.secure = false;
  }
  async function grantToken(claims, res) {
    let jwt = await Keypairs.signJwt({
      jwk: keypair.private,
      iss: iss,
      exp: "24h",
      // optional claims
      claims: claims,
    });
    return { id_token: jwt };
  }

  // fill in ID claims defaults
  async function _getIdClaims(opts) {
    let claims = await getIdClaims(opts);
    if (!claims.iss && false !== claims.iss) {
      claims.iss = iss;
    }
    return claims;
  }

  // fill in Access claims defaults
  async function _getAccessClaims(opts) {
    let claims = await getAccessClaims(opts);
    if (!claims.iss && false !== claims.iss) {
      claims.iss = iss;
    }
    return claims;
  }

  async function setAuthnRefresher(res, claims) {
    let hours = 7 * 24;
    let jwt = await Keypairs.signJwt({
      jwk: keypair.private,
      iss: iss,
      exp: hours + "h", // same as maxAge
      // optional claims
      claims: claims,
    });

    // TODO use existing expires, if available
    let maxAge = hours * 60 * 60 * 1000;
    let cookieOpts = Object.assign({}, cookieDefaults, { maxAge: maxAge });
    res.cookie("id_token", jwt, cookieOpts);
  }

  async function grantTokenAndCookie(claims, res) {
    let jwt = await Keypairs.signJwt({
      jwk: keypair.private,
      iss: iss,
      exp: "24h",
      // optional claims
      claims: claims,
    });
    await setAuthnRefresher(res, claims);
    return { id_token: jwt };
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

  //
  // API Middleware & Handlers
  //
  app.use("/api/authn/", bodyParser.json({ limit: "100kb" }));
  app.use("/api/authn/", cookieParser(COOKIE_SECRET));
  app.post("/api/authn/session", async function (req, res) {
    let claims = await _getIdClaims({
      credentials: req.body,
      claims: req.body,
    });
    return grantTokenAndCookie(claims, res);
  });
  app.post(
    "/api/authn/session/oidc/google.com",
    verifyGoogleToken(process.env.GOOGLE_CLIENT_ID, googleVerifierOpts),
    async function (req, res) {
      let claims = await _getIdClaims({
        email: req.jws.claims.email,
        iss: req.jws.claims.iss,
        ppid: req.jws.claims.sub,
        claims: req.body,
      });
      return grantTokenAndCookie(claims, res);
    }
  );
  app.delete("/api/authn/session", async function (req, res) {
    let now = Date.now() - 10 * 60 * 1000;
    let expired = new Date(now);
    let cookieOpts = Object.assign({}, cookieDefaults, { expires: expired });
    res.cookie("id_token", "", cookieOpts);
    res.json({ success: true });
  });
  app.post("/api/authn/refresh", async function (req, res) {
    let jws = await verifySession(req);
    let claims = await _getIdClaims({ jws: jws, claims: req.body });
    return grantToken(claims, res);
  });
  app.post("/api/authn/exchange", async function (req, res) {
    let jws = await verifyIdToken(req);
    let claims = await _getAccessClaims({ jws: jws, claims: req.body });
    let jwt = await Keypairs.signJwt({
      jwk: keypair.private,
      iss: iss,
      exp: "24h",
      // optional claims
      claims: claims,
    });

    return { access_token: jwt };
  });

  //
  // Error Handlers
  //
  app.use("/api/authn/", function apiNotFoundHandler(req, res) {
    res.statusCode = 404;
    res.json({
      status: 404,
      code: "NOT_FOUND",
      message:
        "The API resource you requested does not exist. Double check for typos and try again.",
    });
  });

  app.wellKnown = require("@root/async-router").Router();
  app.wellKnown.get("/.well-known/openid-configuration", async function () {
    return {
      iss: iss,
      jwks_uri: iss + "/.well-known/jwks.json",
    };
  });
  app.wellKnown.get("/.well-known/jwks.json", async function () {
    return { keys: [keypair.public] };
  });

  return app;
};
