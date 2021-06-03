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
  expires: 0, // should be set on each issuance
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
if ("DEVELOPMENT" === process.env.ENV) {
  cookieDefaults.secure = false;
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

async function verifyUser(req) {
  // TODO validate Google Sign In id_token or magic link
  // (or username and password if you're a bad person)
  if (!req.body.is_verified) {
    let err = new Error("Invalid login credentials");
    err.code = "INVALID_CREDENTIALS";
    throw new Error("");
  }

  return true;
}

async function getUserClaims(req) {
  // TODO go into database and get important info
  return { sub: req.body.sub };
}

async function verifySession(req) {
  if (!req.signedCookies.id_token) {
    let err = Error("Missing or invalid session. Logout and login again.");
    err.status = 400;
    err.code = "INVALID_SESSION";
    throw err;
  }
}

async function verifyIdToken(req) {
  let jwt = (req.headers.authorization || "").replace("Bearer ", "");
  let jws = await Keyfetch.jwt.verify(jwt, {
    iss: false, // TODO "https://example.com",
    jwk: keypair.public,
  });
  console.log("JWS?");
  console.log(jws);
  return true;
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
  await verifyUser(req);
  let claims = await getUserClaims(req);
  let jwt = await Keypairs.signJwt({
    jwk: keypair.private,
    iss: false, // TODO "https://example.com",
    exp: "24h",
    // optional claims
    claims: claims,
  });
  await setAuthnRefresher(res, claims);
  return { id_token: jwt };
});
app.post("/api/authn/refresh", async function (req, res) {
  await verifySession(req);
  let claims = await getUserClaims(req);
  let jwt = await Keypairs.signJwt({
    jwk: keypair.private,
    iss: false, // TODO "https://example.com",
    exp: "24h",
    // optional claims
    claims: claims,
  });
  await setAuthnRefresher(res);
  return { id_token: jwt };
});
app.post("/api/authn/exchange", async function (req, res) {
  await verifyIdToken(req);
  let claims = await getUserClaims(req);
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
app.use("/", function defaultErrorHandler(err, req, res, next) {
  console.error("Unexpected Error:");
  console.error(err);
  res.statusCode = 500;
  res.end("Internal Server Error");
});

//
// Server setup / Router export
//
let server = express().use("/", app);
if (require.main === module) {
  let port = process.env.PORT || 3042;
  http.createServer(server).listen(port, function () {
    /* jshint validthis:true */
    console.info("Listening on", this.address());
  });
}
module.exports = app;
