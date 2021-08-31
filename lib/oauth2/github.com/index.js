"use strict";

var E = require("../../errors.js");

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
    let resp2 = await request({
      //url: "https://api.github.com/user",
      url: "https://api.github.com/user/emails",
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: "Token " + token,
      },
      json: true,
    });

    /** @typedef GhEmail
     * @property {string} email
     * @property {boolean} primary
     * @property {boolean} verified
     */

    /** @type {Array<GhEmail>} */
    let emails = resp2.toJSON().body;
    let email;
    if (Array.isArray(emails)) {
      email = emails
        ?.filter(function (identifier) {
          return identifier.verified && identifier.primary;
        })
        .map(function (identifier) {
          return identifier.email;
        })[0];
    }
    if (!email) {
      throw E.UNVERIFIED_OIDC_IDENTIFIER("email");
    }

    //@ts-ignore
    req._oauth2 = {
      //id: id,
      //name: name,
      email: email,
      iss: "https://github.com",
      issuer: "https://github.com",
    };
    next();
  };
}

/**
 * @param {Oauth2MiddlewareOpts & { _gh: any }} opts
 */
function authorize({ app, _gh, opts, _getClaims, grantTokensAndCookie }) {
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

  /** @type {import('express').Handler} */
  let byGitHubOauth2 = async function (req, res) {
    //@ts-ignore
    req[opts.authnParam] = {
      strategy: "oauth2",
      //@ts-ignore
      email: req._oauth2.email,
      //@ts-ignore
      iss: req._oauth2.iss,
      //@ts-ignore
      id: req._oauth2.id, // TODO
      //@ts-ignore
      oauth2_profile: req._oauth2,
    };
    let allClaims = await _getClaims(req);
    //@ts-ignore
    req[opts.authnParam] = null;
    // TODO delete req._oauth2? (and for oidc too?)

    let tokens = await grantTokensAndCookie(allClaims, req, res);
    res.json(tokens);
  };

  app.post(
    "/session/oauth2/github.com",
    verifyGitHubToken(/*{}*/),
    byGitHubOauth2
  );
}

module.exports = authorize;
