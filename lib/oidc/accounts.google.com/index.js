"use strict";

var E = require("../../errors.js");

module.exports = function ({
  app,
  opts,
  _getClaims,
  grantTokensAndCookie,
  verifyOidcToken,
}) {
  function verifyGoogleToken(clientId, verifyOpts) {
    if (!verifyOpts) {
      verifyOpts = {};
    }
    verifyOpts.iss = "https://accounts.google.com";
    return verifyOidcToken(verifyOpts, async function verifier(jws) {
      if (jws.claims.azp != clientId) {
        throw E.SUSPICIOUS_TOKEN();
      }
      if (!jws.claims.email_verified) {
        throw E.UNVERIFIED_OIDC_IDENTIFIER("email");
      }
    });
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

  let byOidc = async function (req, res) {
    req[opts.authnParam] = {
      strategy: "oidc",
      email: req._jws.claims.email,
      iss: req._jws.claims.iss,
      ppid: req._jws.claims.sub,
      oidc_claims: req._jws.claims,
    };
    let allClaims = await _getClaims(req);
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
};
