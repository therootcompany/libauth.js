"use strict";

var E = require("../../errors.js");

/**
 * @param {OidcMiddlewareOpts} opts
 * @returns {import('express').Handler}
 */
function create({
  opts,
  _issuerName,
  _strategyHandler,
  grantTokensAndCookie,
  verifyOidcToken,
}) {
  /**
   * @param {string} clientId
   * @param {OidcVerifyOpts} verifyOpts
   * @param {import('express').Handler} byOidc
   * @returns {import('express').Handler}
   */
  function verifyGoogleToken(clientId, verifyOpts, byOidc) {
    if (!verifyOpts) {
      verifyOpts = {};
    }
    verifyOpts.iss = `https://${_issuerName}`;
    let verifier = verifyOidcToken(
      verifyOpts,
      /**
       * @param {Jws} jws
       */
      async function _tokenVerifier(jws) {
        // TODO is this azp logic specific to google?
        if (jws.claims.azp != clientId) {
          throw E.SUSPICIOUS_TOKEN();
        }
        if (!jws.claims.email_verified) {
          throw E.OIDC_UNVERIFIED_IDENTIFIER("email");
        }
      }
    );

    return chain(verifier, byOidc);
  }

  let google = opts.oidc[_issuerName] || opts.oidc.google;
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
    let allClaims = await _strategyHandler(req, res);
    //@ts-ignore
    req[opts.authnParam] = null;

    // TODO deprecate
    if (allClaims || !res.headersSent) {
      let tokens = await grantTokensAndCookie(allClaims, req, res);
      res.json(tokens);
    }
  };

  return verifyGoogleToken(google.clientId, googleVerifierOpts, byOidc);
}

/**
 * @param {import('express').Handler} mw1
 * @param {import('express').Handler} mw2
 * @returns {import('express').Handler}
 */
function chain(mw1, mw2) {
  // Please excuse the ugly, but I needed both `express.Handler`s
  // to execute as one. ¯\_(ツ)_/¯
  return function (req, res, next) {
    return Promise.resolve(async function () {
      /// @ts-ignore (for next / error handler)
      await mw1(req, res, function (err) {
        if (err) {
          throw err;
        }
        return Promise.resolve(async function () {
          await mw2(req, res, next);
        }).catch(next);
      });
    }).catch(next);
  };
}

module.exports.create = create;
