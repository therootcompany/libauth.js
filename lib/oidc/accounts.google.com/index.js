"use strict";

var E = require("../../errors.js");
var OIDC = require("../");
var crypto = require("crypto");

// TODO initialize and require from ./lib/request.js
let request = require("@root/request");

function toUrlBase64(val) {
  return Buffer.from(val)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * @param {OidcMiddlewareOpts} opts
 */
function authorize({
  app,
  opts,
  _strategyHandler,
  grantTokensAndCookie,
  verifyOidcToken,
}) {
  let issuer = "https://accounts.google.com";

  /**
   * @param {string} clientId
   * @param {OidcVerifyOpts} verifyOpts
   */
  function verifyGoogleToken(clientId, verifyOpts) {
    if (!verifyOpts) {
      verifyOpts = {};
    }
    verifyOpts.iss = issuer;
    return verifyOidcToken(
      verifyOpts,
      /**
       * @param {Jws} jws
       */
      async function _tokenVerifier(jws) {
        if (jws.claims.azp != clientId) {
          throw E.SUSPICIOUS_TOKEN();
        }
        if (!jws.claims.email_verified) {
          throw E.OIDC_UNVERIFIED_IDENTIFIER("email");
        }
      }
    );
  }

  async function fetchOidcConfig(req, res, next) {
    req.oidcConfig = await OIDC.getConfig(issuer);
    next();
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
    let allClaims = await _strategyHandler(req, res);
    //@ts-ignore
    req[opts.authnParam] = null;

    // TODO deprecate
    if (allClaims || !res.headersSent) {
      let tokens = await grantTokensAndCookie(allClaims, req, res);
      if (!req._oidc_noreply) {
        res.json(tokens);
      } else {
        // TODO return tokens;?
      }
    }
  };

  function redirectGoogleSignIn(clientId, loginUrl) {
    let trustedUrl = loginUrl || opts.issuer;
    if (!trustedUrl) {
      throw Error("[auth3000] [google] no issuer / loginUrl given");
    }

    // ensure the url ends with '/' for the purposes of checking
    if ("/" !== trustedUrl[trustedUrl.length - 1]) {
      trustedUrl = `${trustedUrl}/`;
    }

    /**
     * @param {String} trusted - the base URL that we trust
     * @param {String} untrusted - the redirect URL
     * @returns {Boolean}
     */
    function prefixesUrl(untrustedUrl) {
      if ("/" !== untrustedUrl[untrustedUrl.length - 1]) {
        untrustedUrl = `${untrustedUrl}/`;
      }

      // TODO throw instead of false?
      return untrustedUrl.startsWith(trustedUrl);
    }

    async function redirectToGoogle(req, res) {
      //var oidcAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth";
      var oidcAuthUrl = req.oidcConfig.authorization_endpoint;
      let requestedRedirect = req.headers.referer || trustedUrl;

      let isUnsafe = !prefixesUrl(trustedUrl, requestedRedirect);
      if (isUnsafe) {
        res.statusCode = 500;
        res.end(
          `invalid redirect URL: '${requestedRedirect}' is not child of '${trustedUrl}'`
        );
        return;
      }

      // TODO use base62 crc32
      let state = {
        u: requestedRedirect,
        r: crypto.randomInt(Math.pow(2, 32) - 1).toString(16),
      };
      state = toUrlBase64(JSON.stringify(state));

      let selfUrl = req.originalUrl || req.url;
      selfUrl = new URL(`https://example.com${selfUrl}`).pathname;
      selfUrl = `${opts.issuer}${selfUrl}`;

      let url = OIDC.generateOidcUrl(
        oidcAuthUrl,
        clientId,
        // ex: https://app.example.com/api/authn/session/oidc/accounts.google.com/redirect
        selfUrl,
        state,
        req.query.scope || "email profile",
        req.query.login_hint
      );

      // "Found" (a.k.a. temporary redirect)
      res.redirect(302, url);
    }

    async function complete(req, res) {
      let state = JSON.parse(Buffer.from(req.query.state, "base64"));
      let finalUrl = state.u;

      let isUnsafe = !prefixesUrl(trustedUrl, finalUrl);
      if (isUnsafe) {
        res.statusCode = 500;
        res.end(
          `invalid redirect URL: '${finalUrl}' is not child of '${trustedUrl}'`
        );
        return;
      }

      // don't pass these to the front end
      // TODO remove rather than set undefined
      req.query.state = "";
      if (req.query.id_token) {
        req.query.id_token = "";
      }
      if (req.query.access_token) {
        req.query.access_token = "";
      }
      // pass what google gave us (such as errors) to the front end
      let search = new URLSearchParams(req.query).toString();

      if (finalUrl.includes("?")) {
        finalUrl = `${finalUrl}&${search}`;
      } else {
        finalUrl = `${finalUrl}?${search}`;
      }

      req._oidc_noreply = true;
      if (req.headers.authorization) {
        await byOidc(req, res);
      }

      // "Found" (a.k.a. temporary redirect)
      res.redirect(302, finalUrl);
    }

    return async function (req, res) {
      // Front End requested Google Sign-In Redirect
      if (!req.query.state) {
        await redirectToGoogle(req, res);
        return;
      }

      await complete(req, res);
    };
  }

  // This handles two scenarios:
  // 1. Front end initiates Google Sign-In OIDC redirect process
  //    (browser is redirected to google)
  // 2. Google responds with token and/or failure
  //    (browser is redirected back to the initial referrer)
  //    (TODO: allow client-side redirect_uri)
  app.get(
    "/session/oidc/accounts.google.com/redirect",
    fetchOidcConfig,
    async function _upgradeGoogleResponse(req, res, next) {
      var oidcTokenUrl = req.oidcConfig.token_endpoint;
      // (2) a little monkey patch to switche Google's id_token query param
      // to a Bearer, because that's what the existing token verifier expects
      if (!req.query.code) {
        next();
        return;
      }

      let clientId = google.clientId;
      let clientSecret = google.clientSecret;
      let code = req.query.code;

      let selfUrl = req.originalUrl || req.url;
      selfUrl = new URL(`https://example.com${selfUrl}`).pathname;
      selfUrl = `${opts.issuer}${selfUrl}`;

      let resp = await request({
        method: "POST",
        url: oidcTokenUrl,
        // www-urlencoded...
        json: true,
        form: {
          client_id: clientId,
          client_secret: clientSecret,
          code: code,
          grant_type: "authorization_code",
          redirect_uri: selfUrl,
        },
      });

      let id_token = resp.toJSON().body.id_token;

      req.headers.authorization = `Bearer ${id_token}`;
      next();
    },
    verifyGoogleToken(
      google.clientId,
      // (1) Optional because the process starts with a request for an id_token
      // (and obviously no id_token can be present yet)
      Object.assign({ _optional: true }, googleVerifierOpts)
    ),
    redirectGoogleSignIn(google.clientId, google.loginUrl)
  );

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
