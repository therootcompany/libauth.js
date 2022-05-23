"use strict";

let OIDC = module.exports;

let Crypto = require("crypto");

let E = require("./errors.js");

// JWT Stuff
//@ts-ignore
let Keyfetch = require("keyfetch");

//@ts-ignore
let request = require("@root/request");

/*
OIDC._queryparse = function (search) {
  let params = {};
  new URLSearchParams(search).forEach(function (v, k) {
    // Note: technically the same key _could_ come twice
    // ex: 'names[]=aj&names[]=ryan'
    // (but we're ignoring that case)
    params[k] = v;
  });
  return params;
};
*/

/**
 * @param {LibAuth} libauth
 * @param {LibAuthOpts} libOpts
 */
OIDC.create = function (libauth, libOpts) {
  /**
   * @param {any} pluginOpts
   */
  return function _oidc(pluginOpts) {
    let oidcOpts = Object.assign({}, pluginOpts);

    // TODO initialize and require from ./lib/request.js
    //@ts-ignore
    let request = require("@root/request");

    let OIDC = require("./oidc.js");

    /**
     * Verifies a 3rd-Party Token
     * @param {any} jwt
     * @param {OidcVerifyOpts} verifyOpts
     */
    async function _oidcVerifyToken(jwt, verifyOpts) {
      let keyfetchOpts = {
        issuers: [verifyOpts.iss],
        exp: verifyOpts.exp ?? true,
      };

      // JWS is the technical term for a decoded JWT
      let jws = await Keyfetch.jwt.verify(jwt, keyfetchOpts);

      if ("function" === typeof verifyOpts.pluginVerify) {
        verifyOpts.pluginVerify(jws);
      }

      if (jws.claims.email) {
        // lowercase, just in case
        jws.claims.email = jws.claims.email.toLowerCase();
        // check email_verified, just in case
        if (false !== verifyOpts.email_verified && !jws.claims.email_verified) {
          throw E.OIDC_UNVERIFIED_IDENTIFIER("email");
        }
      }

      return jws;
    }

    /**
     * @param {String} str
     */
    function startsWithProto(str) {
      // https:// http:// app: custom-x:
      let colonAt = str.indexOf(":");
      if (colonAt < 1) {
        return false;
      }
      if (colonAt < 10) {
        return true;
      }
      return false;
    }

    /**
     * @param {String} str
     */
    function stripTrailingSlash(str) {
      if (!str.endsWith("/")) {
        return str;
      }
      return str.slice(0, -1);
    }

    /** @type {import('express').Handler} */
    async function generateAuthUrl(req, res, next) {
      if (req.query.code || req.query.error) {
        next();
        return;
      }

      //let oidcAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth";
      let oidcConfig = await OIDC.getConfig(pluginOpts.issuer);

      // ex: https://app.example.com/api/authn/session/oidc/accounts.google.com/redirect
      if (!pluginOpts.redirectUri) {
        pluginOpts.redirectUri = req.originalUrl || req.url;
      }
      // TODO SECURITY check redirectUri
      if (!startsWithProto(pluginOpts.redirectUri)) {
        let redirectBase = "";
        if (!startsWithProto(libOpts.issuer)) {
          redirectBase += "https://";
        }
        redirectBase += stripTrailingSlash(libOpts.issuer);
        pluginOpts.redirectUri = `${redirectBase}${pluginOpts.redirectUri}`;
      }

      let state = Crypto.randomInt(Math.pow(2, 32) - 1).toString(16);

      /* { clientId, scope } */
      let query = Object.assign(pluginOpts.authQuery, req.query, {
        redirect_uri: pluginOpts.redirectUri,
        state: state,
        response_type: "code",
      });

      let url = OIDC.generateOidcUrl(oidcConfig.authorization_endpoint, query);

      libauth.set(req, {
        strategy: "oidc_auth",
        authUrl: url.toString(),
      });

      next();
    }

    /** @type {import('express').Handler} */
    async function redirectToAuthUrl(req, res, next) {
      let authUrl = libauth.get(req, "authUrl");
      if (!authUrl) {
        next();
        return;
      }

      // TODO XXXX hand control back?
      // "Found" (a.k.a. temporary redirect)
      res.redirect(302, authUrl);
    }

    /** @type {import('express').Handler} */
    async function readCodeParams(req, res, next) {
      let clientId = pluginOpts.clientId;
      let clientSecret = pluginOpts.clientSecret;
      let code = req.query.code;

      if (!pluginOpts.redirectUri) {
        let ownPath = req.originalUrl || req.url;
        ownPath = new URL(`https://example.com${ownPath}`).pathname;
        let issuer = libOpts.issuer;
        if (issuer.endsWith("/")) {
          issuer = issuer.slice(0, -1);
        }
        pluginOpts.redirectUri = `${issuer}${ownPath}`;
      }

      let form = {
        client_id: clientId,
        client_secret: clientSecret,
        code: code,
        grant_type: "authorization_code",
        redirect_uri: pluginOpts.redirectUri,
      };

      libauth.set(req, {
        strategy: "oidc_code",
        oidcRequest: form,
      });

      next();
    }

    /** @type {import('express').Handler} */
    async function requestToken(req, res, next) {
      let oidcTokenRequest = libauth.get(req, "oidcRequest");
      let oidcConfig = await OIDC.getConfig(pluginOpts.issuer);
      // TODO get the code and exchange it
      let resp = await request({
        method: "POST",
        url: oidcConfig.token_endpoint,
        // www-urlencoded...
        json: true,
        form: oidcTokenRequest,
      });
      console.log("[DEBUG] google resp.body:", resp.body);

      libauth.set(req, {
        strategy: "oidc_code",
        oidcResponse: resp.body,
      });

      next();
    }

    /** @type {import('express').Handler} */
    async function verifyToken(req, res, next) {
      // For POST 'Implicit Grant' (Client-Side) Flow
      let jwt = (req.headers.authorization || "").replace(/^Bearer /, "");

      if (!jwt) {
        // For GET 'Authorization Code' (Server-Side Redirects) Flow
        let oidcResponse = libauth.get(req, "oidcResponse");
        jwt = oidcResponse?.id_token || oidcResponse?.access_token;

        if (!jwt) {
          libauth.set(
            req,
            "oidcError",
            oidcResponse || {
              error: "libauth:invalid_oidc_response",
              error_description: "did not receive response from oidc provider",
            },
          );
          next(E.OIDC_ERROR());
          return;
        }
      }

      let jws = await _oidcVerifyToken(jwt, oidcOpts.claims);

      libauth.set(req, {
        strategy: "oidc",
        oidcJws: jws,
        oidcClaims: jws?.claims,
        //
        email: jws.claims.email,
        iss: jws.claims.iss,
        ppid: jws.claims.sub,
      });

      next();
    }

    return {
      // TODO make sure we're using the standard names
      generateAuthUrl: libauth.promisifyHandler(generateAuthUrl),
      redirectToAuthUrl: libauth.promisifyHandler(redirectToAuthUrl),
      readCodeParams: libauth.promisifyHandler(readCodeParams),
      requestToken: libauth.promisifyHandler(requestToken),
      verifyToken: libauth.promisifyHandler(verifyToken),
    };
  };
};

/**
 * @param {String} oidcBaseUrl
 * @param {Object} query
 * @param {String} query.client_id
 * @param {String} query.redirect_uri
 * @param {String} query.state
 * @param {String} query.scope
 * @param {String} query.login_hint
 * @param {String} query.response_type
 * @returns {URL}
 */
OIDC.generateOidcUrl = function (oidcBaseUrl, query) {
  // response_type=id_token requires a nonce (one-time use random value)
  // response_type=token (access token) does not
  var nonce = Crypto.randomUUID().replace(/-/g, "");
  var options = Object.assign({}, query, { nonce });
  // transform from object to 'param1=escaped1&param2=escaped2...'
  var params = new URLSearchParams(options).toString();

  let urlStr = `${oidcBaseUrl}?${params}`;
  return new URL(urlStr);
};

// TODO @root/request
/** @param {any} resp */
async function mustOk(resp) {
  if (resp.ok) {
    return resp;
  }
  throw E.OIDC_BAD_GATEWAY();
}

/**
 * @typedef OIDCCache
 * @property {Number} exp
 * @property {any} config
 */

/** @type Record<String,OIDCCache> */
OIDC._configs = {};

/** @param {String} issuer */
OIDC.getConfig = async function (issuer) {
  let oidcUrl = issuer;
  if (!oidcUrl.endsWith("/")) {
    oidcUrl += "/";
  }
  oidcUrl += ".well-known/openid-configuration";
  if (OIDC._configs[oidcUrl]) {
    if (OIDC._configs[oidcUrl].exp - Date.now() > 0) {
      return OIDC._configs[oidcUrl].config;
    }
  }

  // See examples:
  // Google: https://accounts.google.com/.well-known/openid-configuration
  // Auth0: https://example.auth0.com/.well-known/openid-configuration
  // Okta: https://login.writesharper.com/.well-known/openid-configuration
  let resp = await request({ url: oidcUrl, json: true })
    .then(mustOk)
    //@ts-ignore
    .catch(function (err) {
      console.error(`Could not get '${oidcUrl}':`);
      console.error(err);

      throw E.OIDC_BAD_REMOTE();
    });

  // TODO use cache headers for time
  OIDC._configs[oidcUrl] = {
    config: resp.body,
    exp: Date.now() + 5 * 60 * 1000,
  };

  return resp.body;
};
