"use strict";

require("dotenv").config({ path: ".env" });
require("dotenv").config({ path: ".env.secret" });

let FsSync = require("fs");
let http = require("http");

let express = require("express");
let LibAuth = require("../");

let issuer = process.env.BASE_URL || `http://localhost:${process.env.PORT}`;
let privkey = JSON.parse(FsSync.readFileSync("./key.jwk.json", "utf8"));

let app = express.Router();

let libauth = LibAuth.create(issuer, privkey, {
  cookie: { path: "/api/authn/" },
  /*
    refreshCookiePath: "/api/authn/",
    accessCookiePath: "/api/assets/",
  */
});

let MyAuth = require("./my-auth.js");

function greet(req, res) {
  return { message: "Hello, World!" };
}

// Dev / Localhost Stuff
if ("DEVELOPMENT" === process.env.NODE_ENV) {
  // more logging
  let morgan = require("morgan");
  app.use("/", morgan("tiny"));
}
app.get("/hello", greet);

let bodyParser = require("body-parser");
app.use("/api", bodyParser.json({ limit: "100kb" }));

let cookieParser = require("cookie-parser");
let cookieSecret = process.env.HMAC_SECRET || process.env.COOKIE_SECRET;
app.use("/api/authn", cookieParser(cookieSecret)); // needed to set cookies?

//app.use("/api/authn/", libauth.initialize());

app.post(
  "/api/authn/session/credentials",
  libauth.readCredentials(),
  MyAuth.getUserClaimsByPassword,
  libauth.newSession(),
  libauth.initClaims(),
  libauth.initTokens(),
  libauth.initCookie(),
  MyAuth.expireCurrentSession,
  MyAuth.saveNewSession,
  libauth.setCookieHeader(),
  libauth.sendTokens(),
);

if (MyAuth.sendCodeToUser && MyAuth.ChallengeStore) {
  // Magic Link (challenge-based auth)
  let magic = libauth.challenge({
    Store: MyAuth.ChallengeStore,
    duration: "24h",
    maxAttempts: 5,
    magicSalt: privkey.d,
  });

  app.post(
    "/api/authn/challenge",
    magic.readParams,
    magic.generateChallenge,
    MyAuth.sendCodeToUser,
    magic.saveChallenge,
    magic.sendReceipt,
  );

  // TODO websocket so you don't have to poll
  app.get(
    "/api/authn/challenge/:id",
    magic.readParams,
    magic.getChallenge,
    magic.checkStatus,
    magic.saveFailedChallenge,
    magic.sendStatus,
  );

  app.post(
    "/api/authn/session/challenge/:id",
    magic.readParams,
    magic.getChallenge,
    magic.checkStatus,
    magic.exchange,
    magic.saveChallenge,
    // Handle failed attempt
    magic.saveFailedChallenge,

    MyAuth.getUserClaimsByIdentifier,
    libauth.newSession(),
    libauth.initClaims(),
    libauth.initTokens(),
    libauth.initCookie(),
    MyAuth.expireCurrentSession,
    MyAuth.saveNewSession,
    libauth.setCookieHeader(),
    libauth.sendTokens(),
  );

  app.delete(
    "/api/authn/challenge/:id",
    magic.readParams,
    magic.getChallenge,
    magic.checkStatus,
    magic.saveFailedChallenge,
    magic.cancelChallenge,
    magic.saveChallenge,
    magic.sendStatus,
  );
}

// Google Sign In
if (process.env.GOOGLE_CLIENT_ID) {
  let googleOidc = libauth.oidc(
    //require("@libauth/oidc-google")
    require("../plugins/oidc-google/")({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      redirectUri: "/api/authn/session/oidc/accounts.google.com/code",
    }),
  );

  //
  // For 'Authorization Code' (Server-Side Redirects) Flow
  // (requires `clientId` and `clientSecret`)
  //
  if (process.env.GOOGLE_CLIENT_SECRET) {
    app.get(
      "/api/authn/oidc/accounts.google.com/auth",
      googleOidc.generateAuthUrl,
      googleOidc.redirectToAuthUrl,
    );
    app.get(
      "/api/authn/session/oidc/accounts.google.com/code",
      googleOidc.readCodeParams,
      googleOidc.requestToken,
      googleOidc.verifyToken,
      MyAuth.getUserClaimsByOidcEmail,
      libauth.newSession(),
      libauth.initClaims(),
      libauth.initTokens(),
      libauth.initCookie(),
      MyAuth.expireCurrentSession,
      MyAuth.saveNewSession,
      libauth.setCookieHeader(),
      libauth.captureError(),
      libauth.redirectWithQuery("/#"),
    );
  }

  //
  // For 'Implicit Grant' (Client-Side) Flow
  // (requires `clientId` only)
  //
  app.post(
    "/api/authn/session/oidc/accounts.google.com/token",
    googleOidc.verifyToken,
    MyAuth.getUserClaimsByOidcEmail,
    libauth.newSession(),
    libauth.initClaims(),
    libauth.initCookie(),
    libauth.initTokens(),
    MyAuth.expireCurrentSession,
    MyAuth.saveNewSession,
    libauth.setCookieHeader(),
    libauth.sendTokens(),
  );
}

// TODO let gh = require('@libauth/github').create()
/*
  let oauth2Routes = libauth.oauth2({
    "github.com": {
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
    },
  });
  let gh = oauth2Routes["github.com"];
  */
/*
  // For exchanging an implicit-grant (browser-side) token
  app.post("api/authn/session/oauth2/github.com", gh.exchangeToken);
  // For exchanging a grant_type=code (redirect) code
  // (set the url in GitHub Application Settings:
  // <https://github.com/organizations/{{YOUR_ORG_HERE}}/settings/applications>)
  app.get(
    "/api/authn/webhooks/oauth2/github.com",
    gh.exchangeCode,
    gh.exchangeToken,
    async function (req, res, next) {
      let user = await DB.get({ github: req.authn.id });

      req.authn.user = user;
      next();
    },
  );
  // Optional Helpers
  app.get("/api/authn/webhooks/oauth2/github.com/emails", gh.emails);
  app.get("/api/authn/webhooks/oauth2/github.com/userinfo", gh.userinfo);
  */

// Logout (delete session cookie)
app.delete(
  // "/api/session",
  "/api/authn/session",
  libauth.readCookie(),
  MyAuth.expireCurrentSession,
  libauth.expireCookie(),
  libauth.sendOk({ success: true }),
  libauth.sendError({ success: true }),
);

// Refresh ID Token via Session
app.post(
  "/api/authn/session/id_token",
  libauth.requireCookie(),
  MyAuth.getUserClaimsBySub,
  libauth.initClaims({ idClaims: {} }),
  libauth.initTokens(),
  libauth.sendTokens(),
);

// Exchange Access Token via ID Token
app.post(
  "/api/authn/access_token",
  libauth.requireBearerClaims(),
  MyAuth.getUserClaimsBySub,
  libauth.initClaims({ accessClaims: {} }),
  libauth.initTokens(),
  libauth.sendTokens(),
);

app.use("/.well-known/openid-configuration", libauth.wellKnownOidc());
app.use("/.well-known/jwks.json", libauth.wellKnownJwks());

//
// API Middleware & Handlers
//
let authenticate = require("../middleware/");
app.use("/api", authenticate({ iss: issuer, optional: true }));
app.use("/api", function _authz(req, res, next) {
  if (!req.user) {
    // TODO bad idea
    req.user = {};
  }
  if (!req.user.roles) {
    req.user.roles = [];
    if (req.user.role) {
      req.user.roles.push(req.user.role);
    }
  }
  next();
});

if ("DEVELOPMENT" === process.env.NODE_ENV) {
  app.use("/api/debug/inspect", function (req, res) {
    res.json({ success: true, user: req.user || null });
  });
}

//
// Dummies
//
let crypto = require("crypto");
let authorization = require("@ryanburnette/authorization");
let dummies = {};
app.post(
  "/api/dummy",
  authorization({ roles: ["admin"] }),
  function (req, res) {
    let id = crypto.randomBytes(8).toString("hex");
    dummies[id] = Object.assign({}, req.body, { id });
    res.json({
      success: true,
      id: id,
    });
  },
);
app.get(
  "/api/dummy/:id",
  authorization({ roles: ["admin", "user"] }),
  function (req, res) {
    let dummy = dummies[req.params.id];
    if (dummy) {
      res.json({ success: true, result: dummy });
      return;
    }

    res.json({ success: false, code: "NOT_FOUND", message: "invalid id" });
  },
);
app.get("/api/dummy", authorization({ roles: ["admin"] }), function (req, res) {
  let dummyIds = Object.keys(dummies);
  res.json({ success: true, result: dummyIds });
});

//
// Error Handlers
//
app.use("/api/", function apiErrorHandler(err, req, res, next) {
  console.error("[DEBUG] /api", err);
  if ("UNAUTHORIZED" === err.code) {
    err.status = 401;
  }
  if (!err.code) {
    next(err);
    return;
  }

  res.statusCode = err.status || 500;
  if (res.statusCode >= 500) {
    console.error("Unexpected API Error:");
    console.error(err);
  }
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
  err.method = req.method;
  err.path = req.path;
  console.error("Unexpected Error:");
  console.error(err);
  res.statusCode = 500;
  res.end("Internal Server Error");
});

// Dev / Localhost Local File Server
if ("DEVELOPMENT" === process.env.NODE_ENV) {
  let path = require("path");
  app.use("/", express.static(path.join(__dirname, "../public")));
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
