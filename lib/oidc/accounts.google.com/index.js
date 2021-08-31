"use strict";

var E = require("../../errors.js");

/**
 * @param {OidcMiddlewareOpts} opts
 */
function authorize({
  app,
  opts,
  _getClaims,
  grantTokensAndCookie,
  verifyOidcToken,
}) {
  /**
   * @param {string} clientId
   * @param {OidcVerifyOpts} verifyOpts
   */
  function verifyGoogleToken(clientId, verifyOpts) {
    if (!verifyOpts) {
      verifyOpts = {};
    }
    verifyOpts.iss = "https://accounts.google.com";
    return verifyOidcToken(
      verifyOpts,
      /**
       * @param {Jws} jws
       */
      async function verifier(jws) {
        if (jws.claims.azp != clientId) {
          throw E.SUSPICIOUS_TOKEN();
        }
        if (!jws.claims.email_verified) {
          throw E.UNVERIFIED_OIDC_IDENTIFIER("email");
        }
      }
    );
  }

  let google = opts.oidc["accounts.google.com"] || opts.oidc.google;
  let googleVerifierOpts = {};
  if (opts.DEVELOPMENT && !opts.__DEVELOPMENT_2) {
    opts.__DEVELOPMENT_2 = true;
    if (google.clientId) {
      console.info("[auth3000] [ENV=DEVELOPMENT] Allow Expired Google Tokens");
      // allow tests with expired google example token
      googleVerifierOpts.exp = false;
    }
  }

  /** @type {import('express').Handler} */
  let byOidc = async function (req, res) {
    //@ts-ignore
    req[opts.authnParam] = {
      strategy: "oidc",
      //@ts-ignore
      email: req._jws.claims.email,
      //@ts-ignore
      iss: req._jws.claims.iss,
      //@ts-ignore
      ppid: req._jws.claims.sub,
      //@ts-ignore
      oidc_claims: req._jws.claims,
    };
    let allClaims = await _getClaims(req);
    //@ts-ignore
    req[opts.authnParam] = null;

    let tokens = await grantTokensAndCookie(allClaims, req, res);
    res.json(tokens);
  };
  app.post(
    "/session/oidc/accounts.google.com",
    verifyGoogleToken(google.clientId, googleVerifierOpts),
    byOidc
  );
  // deprecated
  app.post(
    "/session/oidc/google.com",
    verifyGoogleToken(google.clientId, googleVerifierOpts),
    byOidc
  );
}

module.exports = authorize;
