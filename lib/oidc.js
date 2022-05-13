"use strict";

let crypto = require("crypto");
let OIDC = module.exports;
let E = require("./errors.js");

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
  var nonce = crypto.randomUUID().replace(/-/g, "");
  var options = Object.assign({}, query, { nonce });
  // transform from object to 'param1=escaped1&param2=escaped2...'
  var params = new URLSearchParams(options).toString();

  let urlStr = `${oidcBaseUrl}?${params}`;
  console.log("DEBUG generateOidcUrl", urlStr);
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
