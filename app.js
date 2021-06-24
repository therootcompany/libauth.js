"use strict";

async function main() {
  require("dotenv").config({ path: ".env" });
  require("dotenv").config({ path: ".env.secret" });

  let http = require("http");
  let express = require("express");
  let app = require("@root/async-router").Router();

  let verifyJwt = require("./lib/middleware.js");
  let issuer = process.env.BASE_URL || `http://localhost:${process.env.PORT}`;

  // TODO reduce boilerplate?
  let Keypairs = require("keypairs");
  let keypair = await Keypairs.parse({ key: process.env.PRIVATE_KEY }).catch(
    function (e) {
      // could not be parsed or was a public key
      console.warn(
        "Warn: PRIVATE_KEY could not be parsed! Generating a temporary key."
      );
      console.warn(e);
      return Keypairs.generate();
    }
  );

  let DB = require("./db.js");
  async function getClaims(req) {
    let { strategy, email, iss, ppid, jws } = req.authn;

    if ("exchange" === strategy) {
      return getAccessClaims(req);
    }

    // TODO credentials
    // TODO MFA
    // TODO ppid vs id vs sub?
    let user = await DB.get({
      email: email || (req.body && req.body.user),
      ppid: ppid,
      id: jws && jws.claims.sub,
    });
    if (req.body && req.body.password) {
      if ("DEVELOPMENT" !== process.env.ENV) {
        throw new Error("creds not implemented");
      }
    }
    if (!user) {
      throw new Error("TODO_NOT_FOUND");
    }

    return {
      claims: {
        sub: user.sub,
        first_name: user.first_name,
        // these are authz things (for an access token), but for the demo...
        //account_id: user.account_id,
        //roles: user.roles,
      },
    };
  }
  async function getAccessClaims(req) {
    let { jws } = req.authn;
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
    if (req.body && req.body.account_id) {
      let account = user.accounts[req.body.account_id];
      user.account_id = undefined;
      if (!account) {
        throw new Error("TODO_BAD_ACCESS_REQUEST");
      }
      user.account_id = account.id;
      user.roles = account.roles;
    }

    return {
      claims: {
        // authn things, but handy
        sub: user.sub,
        first_name: user.first_name,
        // authz things
        account_id: user.account_id,
        roles: user.roles,
      },
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

  async function notify(req) {
    let { type, value, secret, id } = req.authn;
    let request = require("@root/request");
    let rnd = require("./lib/rnd.js");

    if (!process.env.SEND_EMAIL && "DEVELOPMENT" === process.env.ENV) {
      console.debug("[DEV] skipping email send");
      return;
    }

    let preHeader = "";
    let apiKey = process.env.MAILGUN_PRIVATE_KEY;
    let domain = process.env.MAILGUN_DOMAIN;

    let from = process.env.EMAIL_FROM;
    let replyTo = process.env.EMAIL_REPLY_TO;
    let msgDomain = process.env.EMAIL_ID_DOMAIN;

    // TODO use heml + eta for email templates
    let challenge_url = `${issuer}/#login?id=${id}&token=${secret}`;
    let templates = {
      "magic-link": {
        subject: "Verify your email",
        html: `${preHeader}<p>Here's your verification code: ${secret}\n\n<br><br>${challenge_url}</p>`,
        text: `Here's your verification code: ${secret}\n\n${challenge_url}`,
      },
      "forgot-password": {
        subject: "Password Reset Link",
        html: `${preHeader}<p>Here's password reset code: ${secret}\n\n${challenge_url}</p>`,
        text: `Here's password reset code: ${secret}\n\n${challenge_url}`,
      },
    };
    let data = templates[req.body.template];
    if (!data) {
      throw new Error(
        "Developer Error: invalid `template` value '" +
          req.body.template +
          "'. If you're just a regular person seeing this, it's not your fault. we did something wrong on our end."
      );
    }

    let rndval = rnd();
    let resp = await request({
      url: `https://api.mailgun.net/v3/${domain}/messages`,
      auth: `api:${apiKey}`,
      form: {
        from: from,
        "h:Reply-To": replyTo,
        "h:Message-ID": `${rndval}@${msgDomain}`,
        "h:X-Entity-Ref-ID": `${rndval}@${msgDomain}`,
        to: value,
        subject: data.subject,
        html: data.html,
        text: data.text,
      },
    });

    if (resp.statusCode >= 300) {
      var err = new Error("failed to email message");
      err.response = resp;
      throw err;
    }

    return resp;
  }

  let store = {
    _db: {},
    set: async function (id, val) {
      store._db[id] = val;
    },
    get: async function (id) {
      return store._db[id];
    },
  };

  let sessionMiddleware = require("./lib/session.js")(
    issuer,
    process.env.HMAC_SECRET || process.env.COOKIE_SECRET,
    {
      keypair,
      notify: notify,
      store: store,
      getClaims,
      googleClientId: process.env.GOOGLE_CLIENT_ID,
    }
  );

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
  // TODO is one of refresh,exchange redundant?
  // /api/authn/{session,refresh,exchange,challenge,logout}
  app.use("/api/authn", sessionMiddleware);
  // /.well-known/openid-configuration
  // /.well-known/jwks.json
  app.use("/", sessionMiddleware.wellKnown);

  //
  // API Middleware & Handlers
  //
  let bodyParser = require("body-parser");
  app.use("/api", bodyParser.json({ limit: "100kb" }));
  app.use("/api", verifyJwt({ iss: issuer, optional: true }));
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
