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
    DEVELOPMENT: false,
    cookiePath: "/api/authn/",
  });

  let DB = require("./db.js");
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
  let challengeRoutes = libauth.challenge({
    store: memstore,
    maxAge: "24h",
    maxAttempts: 5,
  });

  /*
    // TODO MFA
    let user = await DB.get({
      email: email || (req.body && req.body.user),
      ppid: ppid,
      id: jws && jws.claims.sub,
    });

    let user = await DB.get({
      id: jws && jws.claims.sub,
    });
    if (!user) {
      throw new Error("TODO_NOT_FOUND");
    }
  */

  async function notify(vars) {
    //let vars = req.authn;
    // Notify via CLI
    console.log(vars);
    console.log({
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

  // TODO
  app.post(
    "/api/authn/session/credentials",
    libauth.credentials(/*{
      // Defaults
      basic: true,
      username: "username",
      password: "password",
    }*/),
    async function (req, res, next) {
      // TODO assertSecureCompare?
      req.authn.valid = libauth.secureCompare(
        req.authn.password,
        "my-password",
        6,
      );
      if (!req.authn.valid) {
        let err = new Error("password is too short or doesn't match");
        err.code = "E_CREDENTIALS_INVALID";
        err.status = 400;
        throw err;
      }

      // Note: the behavior of send-magic-link-on-auth-failure
      // belongs to the client side

      next();
    },
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
    challengeRoutes.order,
    async function (req, res) {
      await notify(req.authn);
      res.json(req.authn.order);
    },
  );
  app.get(
    "/api/authn/challenge/status",
    challengeRoutes.checkStatus,
    function (req, res) {
      res.json(req.authn.status);
    },
  );

  app.post(
    // "/api/authn/session/magic/link",
    "/api/authn/challenge/finalize",
    challengeRoutes.useCode,
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
  app.post(
    // "/api/authn/session/magic/receipt",
    "/api/authn/challenge/exchange",
    challengeRoutes.useReceipt,
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

  let oidcRoutes = libauth.oidc({
    "accounts.google.com": { clientId: process.env.GOOGLE_CLIENT_ID },
  });
  app.use(
    "/api/authn/session/oidc/accounts.google.com",
    oidcRoutes["accounts.google.com"],
    async function (req, res, next) {
      // get a new session
      let user = await DB.get({ ppid: req.authn.ppid });

      req.authn.user = user;
      console.log("DEBUG got here 3!", req.authn);
      next();
    },
  );

  // TODO let gh = require('@libauth/github').create()
  let oauth2Routes = libauth.oauth2({
    "github.com": {
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
    },
  });
  let gh = oauth2Routes["github.com"];
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
      console.log("DEBUG refresh authn", req.authn);
      next();
    },
  );
  app.post(
    "/api/authn/exchange",
    libauth.exchange(),
    async function (req, res, next) {
      // get a new access token from an ID token (or refresh token?)
      let user = await DB.get({ id: req.authn.jws.claims.sub });

      req.authn.user = user;
      next();
    },
  );

  // Logout (delete session cookie)
  app.delete(
    "/api/authn/session",
    libauth.logout(),
    async function (req, res, next) {
      // TODO
      // SessionsModel.delete(req.authn.jws.claims.jti);
      res.json({ success: true });
    },
    async function (err, req, res, next) {
      // they weren't logged in anyway
      res.json({ success: true });
    },
  );

  app.use("/api/authn", async function (req, res) {
    let user = req.authn.user;
    let claims = {
      sub: user.sub,
      given_name: user.first_name,
    };
    // TODO set refresh JTI in database
    // TODO expire prior JTI
    await libauth.setCookieIfNewSession(req, res, claims);
    let id_token = await libauth.issueIdToken(claims);
    let access_token = await libauth.issueAccessToken(claims);
    res.json({ access_token, id_token });
  });
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

  // /.well-known/openid-configuration
  // /.well-known/jwks.json
  app.use("/", libauth.wellKnown());

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
