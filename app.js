"use strict";

require("dotenv").config();

let http = require("http");
let express = require("express");
let bodyParser = require("body-parser");
let app = require("@root/async-router").Router();
let morgan = require("morgan");

// Cookie Stuff
// See https://github.com/BeyondCodeBootcamp/beyondcodebootcamp.com/blob/main/articles/express-cookies-cheatsheet.md
let cookieParser = require("cookie-parser");
let COOKIE_SECRET = process.env.COOKIE_SECRET;
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
let PRIVATE_KEY = process.env.PRIVATE_KEY;
let keypair;
Keypairs.parse({ key: PRIVATE_KEY })
  .catch(function (e) {
    // could not be parsed or was a public key
    console.warn(
      "Warn: PRIVATE_KEY could not be parsed! Generating a temporary key."
    );
    console.warn(e);
    return Keypairs.generate();
  })
  .then(function (_keypair) {
    keypair = _keypair;
  });

// Dev / Localhost Stuff
let googleVerifierOpts = {};
if ("DEVELOPMENT" === process.env.ENV) {
  // allow tests with expired google example token
  googleVerifierOpts.exp = false;
  // allow non-https cookies
  cookieDefaults.secure = false;
  // more logging
  app.use("/", morgan("tiny"));
}

//
// User-replacable functions
//
async function setAuthnRefresher(res, claims) {
  let hours = 7 * 24;
  let jwt = await Keypairs.signJwt({
    jwk: keypair.private,
    iss: false, // TODO "https://example.com",
    exp: hours + "h", // same as maxAge
    // optional claims
    claims: claims,
  });

  // TODO use existing expires, if available
  let maxAge = hours * 60 * 60 * 1000;
  let cookieOpts = Object.assign({}, cookieDefaults, { maxAge: maxAge });
  res.cookie("id_token", jwt, cookieOpts);
}

async function getUserByEmail(email) {
  // TODO use DB
  return { sub: email };
}

async function getUserByPassword(req) {
  // TODO validate Google Sign In id_token or magic link
  // (or username and password if you're a bad person)
  if (!req.body.is_verified) {
    let err = new Error("Invalid login credentials");
    err.code = "INVALID_CREDENTIALS";
    throw new Error("");
  }

  // TODO use DB
  return { sub: req.body.sub };
}

async function getUserClaims(user) {
  // TODO go into database and get important info
  return { sub: user.sub };
}

async function verifySession(req) {
  if (!req.signedCookies.id_token) {
    let err = Error("Missing or invalid session. Logout and login again.");
    err.status = 400;
    err.code = "INVALID_SESSION";
    throw err;
  }
  // TODO
  return { sub: "TODO" };
}

async function verifyIdToken(req) {
  let jwt = (req.headers.authorization || "").replace("Bearer ", "");
  let jws = await Keyfetch.jwt.verify(jwt, {
    iss: false, // TODO "https://example.com",
    jwk: keypair.public,
  });
  //console.log("JWS?");
  //console.log(jws);
  return { sub: jws.sub };
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

  return async function (req, res, next) {
    let jwt = (req.headers.authorization || "").replace("Bearer ", "");
    console.log("JWT?");
    console.log(jwt);
    if (!jwt) {
      console.log(req.headers);
    }
    Keyfetch.jwt
      .verify(jwt, verifyOpts)
      .then(async function (decoded) {
        if (decoded.claims.iss != verifyOpts.iss) {
          throw new Error("unexpectedly passed issuer validation");
        }
        await verifier(decoded);
        // "jws" is the technical term for a decoded "jwt"
        req.jws = decoded;
        next();
      })
      .catch(next);
  };
}

async function grantTokenAndCookie(user, res) {
  // TODO fill in how to get user
  let claims = await getUserClaims(user);
  let jwt = await Keypairs.signJwt({
    jwk: keypair.private,
    iss: false, // TODO "https://example.com",
    exp: "24h",
    // optional claims
    claims: claims,
  });
  await setAuthnRefresher(res, claims);
  return { id_token: jwt };
}

async function grantToken(user, res) {
  // TODO fill in how to get user
  let claims = await getUserClaims(user);
  let jwt = await Keypairs.signJwt({
    jwk: keypair.private,
    iss: false, // TODO "https://example.com",
    exp: "24h",
    // optional claims
    claims: claims,
  });
  return { id_token: jwt };
}

app.get("/hello", function (req, res) {
  return { message: "Hello, World!" };
});

//
// API Middleware & Handlers
//
app.use("/api", bodyParser.json({ limit: "100kb" }));
app.use("/api/authn/", cookieParser(COOKIE_SECRET));
app.post("/api/authn/session", async function (req, res) {
  let user = await getUserByPassword(req);
  return grantTokenAndCookie(user, res);
});
app.post(
  "/api/authn/session/oidc/google.com",
  verifyGoogleToken(process.env.GOOGLE_CLIENT_ID, googleVerifierOpts),
  async function (req, res) {
    let user = await getUserByEmail(req.jws.email);
    return grantTokenAndCookie(user, res);
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
  let user = await verifySession(req);
  return grantToken(user, res);
});
app.post("/api/authn/exchange", async function (req, res) {
  // TODO
  let user = await verifyIdToken(req);
  let claims = await getUserClaims(user);
  let jwt = await Keypairs.signJwt({
    jwk: keypair.private,
    iss: false, // TODO "https://example.com",
    exp: "24h",
    // optional claims
    claims: claims,
  });

  return { access_token: jwt };
});

//
// Error Handlers
//
app.use("/api/", function apiErrorHandler(err, req, res, next) {
  if (!err.code) {
    next(err);
    return;
  }

  res.statusCode = err.status || 500;
  res.json({ status: err.status, code: err.code, message: err.message });
});
app.use("/api/", function apiNotFoundHandler(req, res) {
  res.statusCode = 404;
  res.json({
    status: 404,
    code: "NOT_FOUND",
    message:
      "The API resource you requested does not exist. Double check for typos and try again.",
  });
});
app.use("/", function defaultErrorHandler(err, req, res, next) {
  console.error("Unexpected Error:");
  console.error(err);
  res.statusCode = 500;
  res.end("Internal Server Error");
});

// Dev / Localhost Local File Server
if ("DEVELOPMENT" === process.env.ENV) {
  let path = require("path");
  app.use("/", express.static(path.join(__dirname, "public")));
}

//
// Server setup / Router export
//
let server = express().use("/", app);
if (require.main === module) {
  let port = process.env.PORT || 3000;
  http.createServer(server).listen(port, function () {
    /* jshint validthis:true */
    console.info("Listening on", this.address());
  });
}
module.exports = app;
