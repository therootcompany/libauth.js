"use strict";

var E = require("../../errors.js");

/**
 * @typedef GhEmail
 * @property {string} email
 * @property {boolean} primary
 * @property {boolean} verified
 */

function verifyGitHubToken(/*verifyOpts*/) {
  /** @type {import('express').Handler} */
  return async function (req, res, next) {
    //@ts-ignore // TODO
    let request = require("@root/request");
    let token = (req.headers.authorization || "").replace(/^Bearer /, "");

    // See https://docs.github.com/en/rest/reference/users
    // notably: name (given + family? arbitrary?), email,
    // login (suggested username), avatar_url

    // SECURITY: You MUST manually check if an email address is verified:
    // https://docs.github.com/en/rest/reference/users#emails
    let profile = await getProfile(token);

    let emails = await getEmails(token);
    emails.sort(function (a, b) {
      // TODO double check order
      if (a.email === profile.email) {
        return -1;
      }
      if (b.email === profile.email) {
        return 1;
      }
      return 0;
    });
    let email = emails[0];
    if (!email) {
      throw E.OIDC_UNVERIFIED_IDENTIFIER("email");
    }

    //@ts-ignore
    req._oauth2 = {
      id: profile.id,
      sub: profile.id,
      nickname: profile.login,
      //name: name,
      email: email.email,
      email_verified: email.verified,
      iss: "https://github.com",
      issuer: "https://github.com",
      profile: profile,
    };
    next();
  };
}

/**
 * @param {Oauth2MiddlewareOpts & { _gh: any }} opts
 */
function authorize({ app, _gh, opts, _strategyHandler, grantTokensAndCookie }) {
  app.get("/webhooks/oauth2/github.com", async function (req, res) {
    //@ts-ignore
    let request = require("@root/request");
    // https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps#web-application-flow

    let clientId = _gh.clientId;
    let clientSecret = _gh.clientSecret;
    let code = req.query.code;
    // TODO check state
    //let state = req.query.state;

    let resp = await request({
      method: "POST",
      url: "https://github.com/login/oauth/access_token",
      // www-urlencoded...
      form: {
        client_id: clientId,
        client_secret: clientSecret,
        code: code,
        // TODO
        //redirect_uri: process.env.GITHUB_REDIRECT_URI,
      },
    });
    // TODO issuer may not be 1:1 with return url
    var loginUrl = _gh.loginUrl || opts.issuer;
    var url = new URL(
      `${loginUrl}#${resp.toJSON().body}&issuer=github.com&state=${
        req.query.state
      }`
    );

    res.statusCode = 302;
    res.setHeader("Location", url.toString());
    res.end("<!-- Redirecting... -->");
  });

  app.get("/webhooks/oauth2/github.com/emails", async function (req, res) {
    let token = (req.headers.authorization || "").replace(/^Bearer /, "");

    let emails = await getEmails(token);
    res.json(
      emails.map(function (email) {
        return {
          email: email.email,
          email_verified: email.verified,
        };
      })
    );
  });

  app.get("/webhooks/oauth2/github.com/userinfo", async function (req, res) {
    let token = (req.headers.authorization || "").replace(/^Bearer /, "");

    let profile = await getProfile(token);
    res.json(profile);
  });

  /** @type {import('express').Handler} */
  let byGitHubOauth2 = async function (req, res) {
    //@ts-ignore
    req[opts.authnParam] = {
      strategy: "oauth2",
      //@ts-ignore
      email: req._oauth2.email,
      //@ts-ignore
      email_verified: req._oauth2.email_verified,
      //@ts-ignore
      iss: req._oauth2.iss,
      //@ts-ignore
      sub: req._oauth2.sub, // TODO
      //@ts-ignore
      id: req._oauth2.id, // TODO
      //@ts-ignore
      oauth2_profile: req._oauth2.profile,
    };
    let allClaims = await _strategyHandler(req, res);
    //@ts-ignore
    req[opts.authnParam] = null;
    // TODO delete req._oauth2? (and for oidc too?)

    // TODO deprecate
    if (allClaims || !res.headersSent) {
      let tokens = await grantTokensAndCookie(allClaims, req, res);
      res.json(tokens);
    }
  };

  app.post(
    "/session/oauth2/github.com",
    verifyGitHubToken(/*{}*/),
    byGitHubOauth2
  );
}

/**
 * @param {string} token
 * @returns {Promise<GhEmail[]>}
 */
async function getEmails(token) {
  //@ts-ignore // TODO
  let request = require("@root/request");

  let resp2 = await request({
    //url: "https://api.github.com/user",
    url: "https://api.github.com/user/emails",
    headers: {
      Accept: "application/vnd.github.v3+json",
      Authorization: "Token " + token,
    },
    json: true,
  });
  // TODO check 200 OK

  /** @type {Array<GhEmail>} */
  let ghEmails = resp2.toJSON().body;

  if (!Array.isArray(ghEmails)) {
    return [];
  }

  return ghEmails
    .map(function (identifier) {
      // this is probably already done - but just in case
      identifier.email = identifier.email.toLowerCase();
      return identifier;
    })
    .filter(function (identifier) {
      return identifier.verified;
    })
    .sort(function (a, b) {
      if (a.primary && !b.primary) {
        return -1;
      }
      if (!a.primary && b.primary) {
        return 1;
      }

      if (a.verified && !b.verified) {
        return -1;
      }
      if (!a.verified && b.verified) {
        return 1;
      }

      if (a.email < b.email) {
        return -1;
      }
      if (a.email > b.email) {
        return 1;
      }

      // this should be impossible
      return 0;
    });
}

/**
 * @param {string} token
 * @returns {Promise<any>}
 */
async function getProfile(token) {
  //@ts-ignore // TODO
  let request = require("@root/request");

  let resp1 = await request({
    url: "https://api.github.com/user",
    headers: {
      Accept: "application/vnd.github.v3+json",
      Authorization: "Token " + token,
    },
    json: true,
  });
  // TODO check 200 OK

  let profile = resp1.toJSON().body;
  // just in case
  profile.email = profile.email.toLowerCase();
  return profile;
}

module.exports = authorize;
