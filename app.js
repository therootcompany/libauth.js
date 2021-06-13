"use strict";
async function main() {
  require("dotenv").config();

  let crypto = require("crypto");
  let http = require("http");
  let express = require("express");
  let app = require("@root/async-router").Router();
  let bodyParser = require("body-parser");
  let morgan = require("morgan");
  let authorization = require("@ryanburnette/authorization");

  let verifyJwt = require("./lib/middleware.js");
  let DB = require("./db.js");
  let issuer = "http://localhost:" + process.env.PORT;

  // TODO reduce boilerplate?
  let Keypairs = require("keypairs");
  let PRIVATE_KEY = process.env.PRIVATE_KEY;
  let keypair = await Keypairs.parse({ key: PRIVATE_KEY }).catch(function (e) {
    // could not be parsed or was a public key
    console.warn(
      "Warn: PRIVATE_KEY could not be parsed! Generating a temporary key."
    );
    console.warn(e);
    return Keypairs.generate();
  });

  // TODO: signal whether ID Token or Access Token or both should be provided
  async function getIdClaims({ email, iss, ppid, credentials, jws, claims }) {
    // TODO credentials
    // TODO MFA
    // TODO ppid vs id vs sub?
    let user = await DB.get({
      email: email || (credentials && credentials.user),
      ppid: ppid,
      id: jws && jws.claims.sub,
    });
    if (credentials) {
      if ("DEVELOPMENT" !== process.env.ENV) {
        throw new Error("creds not implemented");
      }
    }
    if (!user) {
      throw new Error("TODO_NOT_FOUND");
    }

    return {
      sub: user.sub,
      first_name: user.first_name,
      // these are authz things (for an access token), but for the demo...
      //account_id: user.account_id,
      //roles: user.roles,
    };
  }

  // TODO jws => id_token?
  async function getAccessClaims({ jws, claims }) {
    if (!jws) {
      throw new Error("INVALID_CREDENTIALS");
    }

    let user = await DB.get({
      id: jws && jws.claims.sub,
    });
    if (!user) {
      throw new Error("TODO_NOT_FOUND");
    }

    let account = user.account;
    if (claims && claims.account_id) {
      let account = user.accounts[claims.account_id];
      console.log("claims.account_id", claims.account_id);
      console.log("user.accounts", user.accounts);
      user.account_id = undefined;
      if (!account) {
        throw new Error("TODO_BAD_ACCESS_REQUEST");
      }
      user.account_id = account.id;
      user.roles = account.roles;
    }

    return {
      // authn things, but handy
      sub: user.sub,
      first_name: user.first_name,
      // authz things
      account_id: user.account_id,
      roles: user.roles,
    };
  }

  /*
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
*/

  // Dev / Localhost Stuff
  if ("DEVELOPMENT" === process.env.ENV) {
    // more logging
    app.use("/", morgan("tiny"));
  }

  app.get("/hello", function (req, res) {
    return { message: "Hello, World!" };
  });

  let sessionMiddleware = require("./lib/session.js")({
    iss: issuer,
    getIdClaims: getIdClaims,
    getAccessClaims: getAccessClaims,
  });
  // /api/authn/{session,refresh,exchange}
  app.use("/", sessionMiddleware);
  // /.well-known/openid-configuration
  // /.well-known/jwks.json
  app.use("/", sessionMiddleware.wellKnown);

  //
  // API Middleware & Handlers
  //
  app.use("/api", bodyParser.json({ limit: "100kb" }));
  app.use(
    "/api",
    verifyJwt({
      iss: issuer,
      // TODO this should NOT be necessary!
      //pub: keypair.public,
      strict: false,
    })
  );
  app.use("/api", function (req, res, next) {
    if (req.jws) {
      req.user = req.jws.claims;
    }
    next();
  });

  if ("DEVELOPMENT" === process.env.ENV) {
    app.use("/api/debug/inspect", function (req, res) {
      res.json({ success: true, user: req.user || null });
    });
  }

  let dummies = {};
  app.post(
    "/api/dummy",
    authorization({ roles: ["admin"] }),
    function (req, res) {
      let id = crypto.randomBytes(16).toString("hex");
      dummies[id] = Object.assign({}, req.body, { id });
      res.json({
        success: true,
        id: id,
      });
    }
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
    }
  );
  app.get(
    "/api/dummy",
    authorization({ roles: ["admin"] }),
    function (req, res) {
      let dummyIds = Object.keys(dummies);
      res.json({ success: true, result: dummyIds });
    }
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
}

main().catch(function (err) {
  console.error(err);
});
