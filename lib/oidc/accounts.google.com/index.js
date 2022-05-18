"use strict";

var E = require("../../errors.js");

/**
 * @param {OidcMiddlewareOpts} opts
 * @returns {import('express').Handler}
 */
function create({ opts, _issuerName, verifyOidcToken }) {
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
        // TODO is this azp logic specific to Google?
        if (jws.claims.azp != clientId) {
          throw E.SUSPICIOUS_TOKEN();
        }
        if (!jws.claims.email_verified) {
          throw E.OIDC_UNVERIFIED_IDENTIFIER("email");
        }
      },
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
      oidc_header: req._jws.header,
      //@ts-ignore
      oidc_claims: req._jws.claims,
    };
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

  /** @type {import('express').Handler} */
  function plainHandler1(req, res, next) {
    //@ts-ignore
    return Promise.resolve()
      .then(async function () {
        /// @ts-ignore (for next / error handler)
        await mw1(req, res, plainNext2);
      })
      .catch(next);

    //@ts-ignore
    function plainNext2(err) {
      if (err) {
        throw err;
      }
      return Promise.resolve()
        .then(async function () {
          await mw2(req, res, next);
        })
        .then(next)
        .catch(next);
    }
  }
  return plainHandler1;
}

module.exports.create = create;
