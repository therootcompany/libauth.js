"use strict";

async function main() {
  require("dotenv").config({ path: ".env" });
  require("dotenv").config({ path: ".env.secret" });

  let Fs = require("fs").promises;
  let http = require("http");
  let express = require("express");
  let app = require("@root/async-router").Router();

  let LibAuth = require("../");
  let issuer = process.env.BASE_URL || `http://localhost:${process.env.PORT}`;
  let privkey = JSON.parse(await Fs.readFile("./key.jwk.json", "utf8"));
  let libauth = LibAuth.create(issuer, privkey, {
    cookiePath: "/api/authn/",
  });

  let DB = require("./db.js");
  let MyDB = {};
  let memstore = {
    _db: {},
    set: async function (id, val) {
      memstore._db[id] = val;
    },
    get: async function (id) {
      return memstore._db[id];
    },
  };

  // Magic Link (challenge-based auth)
  let magic = libauth.challenge({
    store: memstore,
    maxAge: "24h",
    maxAttempts: 5,
  });

  async function notify(vars) {
    //let vars = req.authn;
    // Notify via CLI
    console.info(vars);
    console.info({
      subject: `Your Magic Link is here! ${vars.code}.`,
      text:
        `Enter this login code when prompted: ${vars.code}. \n` +
        // `Or login with this link: ${vars.iss}/login/#/${vars.id}/${vars.code}`,
        `Or login with this link: ${vars.iss}/#login?id=${vars.id}&token=${vars.code}`,
    });
  }

  function greet(req, res) {
    return { message: "Hello, World!" };
  }

  // Dev / Localhost Stuff
  if ("DEVELOPMENT" === process.env.ENV) {
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

  //
  // /api/session/token/
  //
  // /api/session/credentials/token
  // /api/redirect/oidc/accounts.google.com/auth
  // /api/session/oidc/accounts.google.com/code
  // /api/session/oidc/accounts.google.com/token

  app.use("/api/authn/", libauth.initialize());

  app.post(
    "/api/authn/session/credentials",
    libauth.credentials(),
    MyDB.getUserClaimsByPassword,
    libauth.newSession(),
    libauth.setClaims(),
    libauth.setTokens(),
    libauth.setCookie(),
    libauth.setCookieHeader(),
    libauth.sendTokens(),
  );

  app.post(
    "/api/authn/challenge/order",
    /*
    async function checkForMfa(req, res, next) {
      let user = DB.get(...)
      //req.authn.state.mfa = user.requires_mfa;
      req.body.state.mfa = user.requires_mfa;
      next();
    },
    */
    magic.newLink,
    MyDB.updateStatus,
    MyDB.notify,
    magic.sendReceipt,
  );
  app.get(
    "/api/authn/challenge/status",
    magic.getStatus,
    MyDB.updateStatus,
    magic.checkStatus,
    magic.sendStatus,
  );

  app.post(
    // "/api/authn/session/magic/link",
    "/api/authn/challenge/finalize",
    magic.exchange,
    MyDB.getUserClaimsByIdentifier,
    libauth.newSession(),
    libauth.setClaims(),
    libauth.setTokens(),
    libauth.setCookie(),
    libauth.setCookieHeader(),
    libauth.sendTokens(),
  );
  app.post(
    // "/api/authn/session/magic/receipt",
    "/api/authn/challenge/exchange",
    magic.useReceipt,
    async function (req, res, next) {
      // get a new session
      let user = await DB.get({
        // TODO check if it's actually email!
        email: req.authn.identifier.value,
      });

      req.authn.user = user;
      next();
    },
  );

  let googleOidc = libauth.oidc(
    require("../plugins/accounts.google.com/")({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      // TODO handle url relative to issuer
      //redirectUri: "/api/authn/session/oidc/accounts.google.com/redirect",
    }),
  );
  app.get(
    //"/api/authn/oidc/accounts.google.com/authorization_redirect",
    "/api/authn/session/oidc/accounts.google.com/redirect",
    googleOidc.authorizationRedirect,
    googleOidc.exchangeCode,
    googleOidc.exchangeToken,
    async function (req, res, next) {
      // get a new session
      let user = await DB.get({ ppid: req.authn.ppid });

      req.authn.user = user;

      let claims = {
        sub: user.sub,
        given_name: user.first_name,
      };
      // TODO set refresh JTI in database
      // TODO expire prior JTI
      await libauth.setCookieIfNewSession(req, res, claims);

      let search = new URLSearchParams(req.query).toString();
      res.redirect(`/?${search}`);
    },
  );
  app.post(
    "/api/authn/session/oidc/accounts.google.com",
    googleOidc.exchangeToken,
    //googleOidc.tokenRedirect,
    async function (req, res, next) {
      // get a new session
      let user = await DB.get({ ppid: req.authn.ppid });

      req.authn.user = user;
      next();
    },
  );

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

  app.post(
    "/api/authn/refresh",
    libauth.refresh(),
    async function (req, res, next) {
      // get a new id token from a refresh token
      let user = await DB.get({ id: req.authn.jws.claims.sub });

      req.authn.user = user;
      next();
    },
  );
  app.post("/api/authn/exchange", libauth.exchange(), MyDB.getUserClaimsById);

  // Logout (delete session cookie)
  app.delete(
    "/api/authn/session",
    libauth.getCookie(),
    MyDB.updateSession(),
    libauth.logout(),
    libauth.sendOk({ success: true }),
    libauth.sendError({ success: true }),
  );

  app.use("/api/authn", async function (err, req, res, next) {
    res.statusCode = err.status || 500;
    if (500 == res.statusCode) {
      console.error(err.stack);
    }
    res.json({
      success: false,
      code: err.code,
      status: err.status,
      message: err.message,
    });
  });

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

  if ("DEVELOPMENT" === process.env.ENV) {
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
  app.get(
    "/api/dummy",
    authorization({ roles: ["admin"] }),
    function (req, res) {
      let dummyIds = Object.keys(dummies);
      res.json({ success: true, result: dummyIds });
    },
  );

  //
  // Error Handlers
  //
  app.use("/api/", function apiErrorHandler(err, req, res, next) {
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

  function userToClaims(user) {
    return {
      // "Subject" the user ID or Pairwise ID (required)
      sub: user.id,

      // ID Token Info (optional)
      given_name: user.first_name,
      family_name: user.first_name,
      picture: user.photo_url,
      email: user.email,
      email_verified: user.email_verified_at || false,
      zoneinfo: user.timezoneName,
      locale: user.localeName,
    };
  }

  MyDB.getUserClaimsById = async function (req, res, next) {
    let userId = libauth.get(req, "bearerClaims").sub;

    // get a new access token from an ID token (or refresh token?)
    let user = await DB.get({ id: userId });

    let idClaims = userToClaims(user);
    libauth.set(req, { idClaims: idClaims, accessClaims: {} });

    next();
  };

  MyDB.getUserClaimsByIdentifier = async function (req, res, next) {
    let email = libauth.get(req, "identifier").value;

    // get a new session
    // TODO check if it's actually email!
    let user = await DB.get({ email: email });

    let idClaims = userToClaims(user);
    libauth.set(req, { idClaims: idClaims, accessClaims: {} });

    next();
  };

  MyDB.getUserClaimsByPassword = async function (req, res, next) {
    let creds = libauth.get(req, "credentials");
    let user = await DB.get({ email: creds.email });

    // TODO assertSecureCompare?
    let valid = libauth.secureCompare(
      creds.password,
      //user.password,
      "my-password",
      6,
    );
    if (!valid) {
      // Note: the behavior of send-magic-link-on-auth-failure
      // belongs to the client side
      let err = new Error("password is too short or doesn't match");
      err.code = "E_CREDENTIALS_INVALID";
      err.status = 400;
      throw err;
    }

    let idClaims = userToClaims(user);
    libauth.set(req, { idClaims: idClaims, accessClaims: {} });

    next();
  };

  // Dev / Localhost Local File Server
  if ("DEVELOPMENT" === process.env.ENV) {
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
}

main().catch(function (err) {
  console.error(err);
});
